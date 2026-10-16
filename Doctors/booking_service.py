"""
Booking / payment state machine.
 
    awaiting_payment --(payment verified)--> pending --> completed
          |                                    |
          +--(timeout / patient backs out)--> expired      (pending -> cancelled via the refund workflow)
 
LOCK ORDER, EVERYWHERE:   Slot  ->  Booking  ->  Transaction / Wallet
Mixing the order (the old code locked booking->slot in some views and slot->booking in
others) is how you get deadlocks under load.
"""
import logging
from decimal import Decimal
from decimal import Decimal, InvalidOperation
from functools import partial
import uuid 
import razorpay
from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone
from datetime import timedelta

from sympy import python
 
from Chat.models import ChatRoom                  
from Users.utils import send_verification
from Doctors.models import Bookings, Slots, Transaction, WalletTransaction
from Users.models import Wallet
 
logger = logging.getLogger(__name__)
 
RESERVATION_MINUTES = 15
 
 
class BookingError(Exception):
    """Expected, user-facing failure. Raised inside atomic() blocks so everything rolls back."""
 
    def __init__(self, message, status_code=409, code="conflict"):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
 
 
# --------------------------------------------------------------------------- helpers
 
def razorpay_client():
    return razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
 
 
def to_paise(amount):
    return int((Decimal(amount) * 100).quantize(Decimal("1")))
 
 
def find_existing_booking(user, key):
    return Bookings.objects.filter(user=user, idempotency_key=key).first()
 
 
def lock_slot_and_booking(booking_id, **filters):
    """Lock slot first, then booking (the global lock order). Returns (booking, slot) or (None, None).
    Call inside transaction.atomic()."""
    slot_id = (
        Bookings.objects.filter(pk=booking_id, **filters)
        .values_list("slots_id", flat=True)
        .first()
    )
    if slot_id is None:
        return None, None
    slot = Slots.objects.select_for_update().get(pk=slot_id)
    booking = Bookings.objects.select_for_update().filter(pk=booking_id, **filters).first()
    if booking is None:
        return None, None
    return booking, slot
 
 
# --------------------------------------------------------------------------- reserve
 
def reserve_slot(user, doctor_id, slot_id, payment_method, key, expected_amount=None):
    """
    Idempotently reserve a slot. Returns (booking, created).
      wallet   -> booking is PAID and 'pending' when this returns
      razorpay -> booking is 'awaiting_payment'; the caller must create/fetch the order
    """
    try:
        return _reserve_slot(user, doctor_id, slot_id, payment_method, key, expected_amount)
    except IntegrityError:
        # A race that row locks cannot stop on every DB (SQLite has none). The DB
        # constraints are the backstop; translate them into a clean answer.
        existing = find_existing_booking(user, key)
        if existing:
            return existing, False
        raise BookingError("This appointment slot is no longer available.", 409, "slot_unavailable")
 
 

def _reserve_slot(user, doctor_id, slot_id, payment_method, key, expected_amount):
    with transaction.atomic():
        slot = Slots.objects.select_for_update().filter(
            pk=slot_id,
            doctor_id=doctor_id,
        ).first()

        if slot is None or slot.is_blocked:
            raise BookingError(
                "This slot is not available for booking.",
                404,
                "slot_not_found",
            )

        # Reuse a booking created with the same idempotency key.
        existing = Bookings.objects.select_for_update().filter(
            user=user,
            idempotency_key=key,
        ).first()

        if existing:
            return existing, False

        now = timezone.now()

        if slot.start_time <= now:
            raise BookingError(
                "This slot has already started.",
                400,
                "slot_in_past",
            )

        if (
            expected_amount is not None
            and expected_amount != slot.amount
        ):
            raise BookingError(
                "The price for this slot has changed. "
                "Please review and try again.",
                409,
                "price_changed",
            )

        active = (
            Bookings.objects.select_for_update()
            .filter(
                slots=slot,
                status__in=Bookings.ACTIVE_STATUSES,
            )
            .first()
        )

        if active is not None:
            stale = active.reservation_expired(now)

            mine = (
                active.status == Bookings.AWAITING_PAYMENT
                and active.user_id == user.id
            )

            if stale:
                active.status = Bookings.EXPIRED
                active.save(update_fields=["status"])

                another_active_booking = (
                    Bookings.objects.filter(
                        slots=slot,
                        status__in=Bookings.ACTIVE_STATUSES,
                    )
                    .exclude(pk=active.pk)
                    .exists()
                )

                if not another_active_booking:
                    slot.is_booked = False
                    slot.save(update_fields=["is_booked"])

            elif mine:
                # Preserve this patient's existing reservation.
                # Do not reset expires_at or create another booking.
                if payment_method != active.payment_method:
                    raise BookingError(
                        "You already have an active reservation. "
                        "Resume or allow it to expire before changing "
                        "the payment method.",
                        409,
                        "active_reservation_exists",
                    )

                return active, False

            else:
                raise BookingError(
                    "This appointment slot is no longer available.",
                    409,
                    "slot_unavailable",
                )

        amount = slot.amount

        if payment_method == "wallet":
            Wallet.objects.get_or_create(user=user)
            wallet = Wallet.objects.select_for_update().get(user=user)

            if wallet.balance < amount:
                raise BookingError(
                    "Insufficient wallet balance.",
                    400,
                    "insufficient_balance",
                )

            booking = Bookings.objects.create(
                user=user,
                doctor_id=slot.doctor_id,
                slots=slot,
                idempotency_key=key,
                payment_method="wallet",
                status=Bookings.PENDING,
            )

            wallet.balance -= amount
            wallet.save(update_fields=["balance"])

            WalletTransaction.objects.create(
                wallet=wallet,
                user=user,
                booking=booking,
                currency="INR",
                amount=amount,
                status="completed",
            )

            ChatRoom.objects.get_or_create(
                patient=user,
                doctor=slot.doctor,
            )

        elif payment_method == "razorpay":
            booking = Bookings.objects.create(
                user=user,
                doctor_id=slot.doctor_id,
                slots=slot,
                idempotency_key=key,
                payment_method="razorpay",
                expires_at=now + timedelta(
                    minutes=RESERVATION_MINUTES
                ),
                status=Bookings.AWAITING_PAYMENT,
            )

        else:
            raise BookingError(
                "Unsupported payment method.",
                400,
                "invalid_payment_method",
            )

        slot.is_booked = True
        slot.save(update_fields=["is_booked"])

        return booking, True


 
# --------------------------------------------------------------------------- razorpay order
 
def ensure_razorpay_order(booking_id):
    """
    Idempotent: returns (booking, payment), creating the Razorpay order at most once.
 
    The booking row stays locked while we call Razorpay. That is deliberate and cheap:
    only retries of THIS booking can contend for it, and it is what stops two concurrent
    retries from creating two orders. Nothing else (slot, wallet) is locked here.
    If Razorpay fails, nothing is written; the patient retries with the same key.
    """
    with transaction.atomic():
        booking = Bookings.objects.select_for_update().get(pk=booking_id)
 
        if booking.status != Bookings.AWAITING_PAYMENT or booking.reservation_expired():
            raise BookingError(
                "Your reservation is no longer active. Please select the slot again.",
                409, "reservation_expired",
            )
 
        payment = (
            Transaction.objects.filter(booking=booking)
            .exclude(razorpay_order_id__isnull=True)
            .first()
        )
        if payment:
            return booking, payment
 
        amount = Slots.objects.values_list("amount", flat=True).get(pk=booking.slots_id)
        order = razorpay_client().order.create(data={
            "amount": to_paise(amount),
            "currency": "INR",
            "receipt": f"booking_{booking.pk}",
            "payment_capture": 1,
            "notes": {"booking_id": str(booking.pk), "user_id": str(booking.user_id)},
        })
        payment = Transaction.objects.create(
            user_id=booking.user_id,
            booking=booking,
            razorpay_order_id=order["id"],
            currency="INR",
            amount=amount,
            status="pending",
        )
        return booking, payment


 
def get_active_reservation(user):
    """
    Return the patient's existing, unexpired Razorpay reservation.

    Does not create a booking, create an order, or extend expiry.
    """
    now = timezone.now()

    bookings = Bookings.objects.filter(
        user=user,
        payment_method="razorpay",
        status=Bookings.AWAITING_PAYMENT,
        expires_at__gt=now,
    ).order_by("-created_at")

    for booking in bookings:
        payment = (
            Transaction.objects.filter(
                booking=booking,
                status="pending",
            )
            .exclude(razorpay_order_id__isnull=True)
            .exclude(razorpay_order_id="")
            .order_by("-created_at")
            .first()
        )

        if payment is None:
            continue

        return {
            "booking_id": booking.pk,
            "doctor_id": booking.doctor_id,
            "slot_id": booking.slots_id,
            "razorpay_order_id": payment.razorpay_order_id,
            "amount": str(payment.amount),
            "amount_paise": to_paise(payment.amount),
            "currency": payment.currency,
            "expires_at": booking.expires_at.isoformat(),
            "remaining_seconds": max(
                0,
                int(
                    (booking.expires_at - now).total_seconds()
                ),
            ),
        }

    return None

 
# --------------------------------------------------------------------------- confirm payment
 
def confirm_razorpay_payment(order_id, payment_id, signature=None, *,
                             user=None, booking_id=None, amount_paise=None):
    """
    The ONLY place a Razorpay payment turns a booking into an appointment.
    Called by the checkout callback AND the webhook, so it must be idempotent.
 
    Returns (outcome, payment):
      confirmed | already_confirmed | refund_required | refunded | mismatch | not_found
    For 'refund_required' the caller must call refund_payment(payment.pk) AFTER this returns.
    """
    filters = {"razorpay_order_id": order_id}
    if user is not None:
        filters["user"] = user
    probe = Transaction.objects.filter(**filters).values("pk", "booking_id").first()
    if probe is None:
        return "not_found", None
 
    slot_id = None
    if probe["booking_id"] is not None:
        slot_id = (
            Bookings.objects.filter(pk=probe["booking_id"])
            .values_list("slots_id", flat=True)
            .first()
        )
 
    with transaction.atomic():
        slot = Slots.objects.select_for_update().get(pk=slot_id) if slot_id else None
        booking = (
            Bookings.objects.select_for_update().filter(pk=probe["booking_id"]).first()
            if slot else None
        )
        payment = Transaction.objects.select_for_update().get(pk=probe["pk"])
 
        if booking_id is not None and (booking is None or str(booking.pk) != str(booking_id)):
            return "mismatch", payment
        if amount_paise is not None and int(amount_paise) != to_paise(payment.amount):
            logger.error("Amount mismatch on order %s: gateway=%s ours=%s",
                         order_id, amount_paise, to_paise(payment.amount))
            return "mismatch", payment
 
        if payment.status == "completed":
            same = payment.payment_id in (None, "", payment_id)
            return ("already_confirmed" if same else "mismatch"), payment
        if payment.status == "refunded":
            return "refunded", payment
        if payment.status == "refund_pending":
            return "refund_required", payment
 
        # Can this patient still be given the slot?
        can_fulfil = False
        if booking is not None:
            if booking.status in (Bookings.AWAITING_PAYMENT, Bookings.PENDING):
                # Even if expires_at just passed: nobody else holds the slot yet (the sweeper
                # needs the slot lock we are holding) and the money is already taken.
                can_fulfil = True
            elif (
                booking.status == Bookings.EXPIRED
                and not slot.is_blocked
                and slot.start_time > timezone.now()
            ):
                # Paid after the hold lapsed. Re-take the slot if nobody else did.
                taken = (
                    Bookings.objects.filter(slots=slot, status__in=Bookings.ACTIVE_STATUSES)
                    .exclude(pk=booking.pk)
                    .exists()
                )
                can_fulfil = not taken
 
        payment.payment_id = payment_id
        if signature:
            payment.razorpay_signature = signature
 
        if not can_fulfil:
            # Money captured, slot gone. Never leave this as 'pending'. Refund it.
            payment.status = "refund_pending"
            payment.save(update_fields=["payment_id", "razorpay_signature", "status", "updated_at"])
            return "refund_required", payment
 
        payment.status = "completed"
        payment.save(update_fields=["payment_id", "razorpay_signature", "status", "updated_at"])
 
        booking.status = Bookings.PENDING
        booking.save(update_fields=["status"])
        if not slot.is_booked:
            slot.is_booked = True
            slot.save(update_fields=["is_booked"])
 
        # Chat access is granted on PAYMENT, not on reservation (it used to be created
        # before the patient had paid anything).
        ChatRoom.objects.get_or_create(patient=booking.user, doctor=booking.doctor)
 
        transaction.on_commit(partial(_send_confirmation, booking.pk, payment.pk))
        return "confirmed", payment
 
 
def _send_confirmation(booking_pk, payment_pk):
    try:
        booking = Bookings.objects.select_related("user", "doctor", "slots").get(pk=booking_pk)
        payment = Transaction.objects.get(pk=payment_pk)
        slot = booking.slots
        send_verification(
            email=booking.user.email,
            doctor_name=f"{booking.doctor.first_name} {booking.doctor.last_name}",
            start_time=slot.start_time,
            end_time=slot.end_time,
            duration=slot.duration,
            date=slot.start_date,
            transaction=payment,
        )
    except Exception:
        logger.exception("Payment confirmed but confirmation email failed (booking %s)", booking_pk)
 
 
# --------------------------------------------------------------------------- refunds
 



def refund_payment(payment_pk):
    """
    Request or reconcile a Razorpay refund.

    Returns:
        refunded
        refund_pending
        refund_processing
        failed
    """

    # Step 1: Claim the refund or decide whether recovery is needed.
    with transaction.atomic():
        payment = Transaction.objects.select_for_update().get(
            pk=payment_pk
        )

        if payment.status == "refunded":
            return "refunded"

        if payment.status == "refund_processing":
            # Give a recent request time to finish.
            recovery_cutoff = timezone.now() - timedelta(minutes=5)

            if payment.updated_at >= recovery_cutoff:
                return "refund_processing"

            # If older than five minutes, reconcile or retry below.
            # Reuse the original idempotency key.

        elif payment.status not in ("completed", "refund_pending"):
            return "failed"

        if not payment.payment_id:
            logger.error(
                "Cannot refund transaction %s: missing Razorpay payment ID",
                payment.pk,
            )
            return "failed"

        if not payment.refund_idempotency_key:
            payment.refund_idempotency_key = str(uuid.uuid4())

        payment.status = "refund_processing"
        payment.save(
            update_fields=[
                "status",
                "refund_idempotency_key",
                "updated_at",
            ]
        )

        refund_id = payment.razorpay_refund_id
        idempotency_key = payment.refund_idempotency_key
        razorpay_payment_id = payment.payment_id
        amount_paise = to_paise(payment.amount)

    # Step 2: Communicate with Razorpay outside the database transaction.
    try:
        client = razorpay_client()

        if refund_id:
            # A refund already exists: check its actual provider status.
            refund = client.refund.fetch(refund_id)
        else:
            # Use the same key and same amount on retries.
            refund = client.payment.refund(
                razorpay_payment_id,
                {"amount": amount_paise},
                headers={
                    "X-Refund-Idempotency": idempotency_key,
                },
            )

        returned_refund_id = refund.get("id")
        provider_status = refund.get("status")

    except Exception:
        logger.exception(
            "Could not confirm Razorpay refund for payment %s",
            razorpay_payment_id,
        )

        # A timeout may occur after Razorpay received the request.
        # Keep the idempotency key so a retry uses the same request.
        with transaction.atomic():
            payment = Transaction.objects.select_for_update().get(
                pk=payment_pk
            )

            if payment.status == "refund_processing":
                payment.status = "refund_pending"
                payment.save(
                    update_fields=["status", "updated_at"]
                )

        return "refund_pending"

    # Step 3: Persist what Razorpay actually reported.
    with transaction.atomic():
        payment = Transaction.objects.select_for_update().get(
            pk=payment_pk
        )

        if returned_refund_id:
            payment.razorpay_refund_id = returned_refund_id

        if provider_status == "processed":
            payment.status = "refunded"

        elif provider_status == "failed":
            # Do not silently create another refund attempt.
            # Preserve the refund ID for investigation.
            payment.status = "refund_failed"

            logger.error(
                "Razorpay reports refund %s failed for payment %s. "
                "Manual review is required before another attempt.",
                returned_refund_id or refund_id,
                razorpay_payment_id,
            )

        else:
            # For example, Razorpay may still report "pending".
            payment.status = "refund_pending"

        payment.save(
            update_fields=[
                "razorpay_refund_id",
                "status",
                "updated_at",
            ]
        )

        if provider_status == "failed":
            return "failed"

        return payment.status

def retry_pending_refunds(limit=50):
    """
    Retry pending refunds and recover stale processing records.
    A processing record is considered stale after five minutes.
    """
    from django.db.models import Q

    recovery_cutoff = timezone.now() - timedelta(minutes=5)

    payment_ids = list(
        Transaction.objects.filter(
            Q(status="refund_pending")
            | Q(
                status="refund_processing",
                updated_at__lt=recovery_cutoff,
            )
        )
        .order_by("updated_at")
        .values_list("pk", flat=True)[:limit]
    )

    refunded_count = 0

    for payment_pk in payment_ids:
        try:
            result = refund_payment(payment_pk)

            if result == "refunded":
                refunded_count += 1

        except Exception:
            logger.exception(
                "Unexpected error retrying refund for transaction %s",
                payment_pk,
            )

    return refunded_count





def cleanup_outdated_slots(batch=500):
    now = timezone.now()

    outdated_slots = Slots.objects.filter(
        end_time__lt=now,
        bookings__isnull=True,
    ).order_by("id")

    slot_ids = list(
        outdated_slots.values_list("id", flat=True)[:batch]
    )

    if not slot_ids:
        return 0

    deleted_count, _ = Slots.objects.filter(
        id__in=slot_ids,
        end_time__lt=now,
        bookings__isnull=True,
    ).delete()

    return deleted_count
 
 
# --------------------------------------------------------------------------- expiry sweeper
 


def expire_stale_reservations(batch=200):
    """
    Expire reservations after the original 15-minute deadline.

    Reconcile Razorpay before releasing a slot:
    - Paid: use the normal confirmation/refund workflow.
    - Safe to release: expire the reservation and release the slot.
    - Pending/unknown/provider unavailable: preserve the reservation.
    """
    now = timezone.now()

    due_ids = list(
        Bookings.objects.filter(
            status=Bookings.AWAITING_PAYMENT,
            expires_at__lte=now,
        )
        .order_by("expires_at", "pk")
        .values_list("pk", flat=True)[:batch]
    )

    released = 0

    for booking_id in due_ids:
        payment_probe = (
            Transaction.objects.filter(booking_id=booking_id)
            .exclude(razorpay_order_id__isnull=True)
            .exclude(razorpay_order_id="")
            .order_by("-created_at")
            .values("pk", "razorpay_order_id", "status")
            .first()
        )

        # If a Razorpay order exists, reconcile it before releasing.
        if payment_probe:
            try:
                state, provider_payment = inspect_razorpay_order(
                    payment_probe["razorpay_order_id"]
                )
            except Exception:
                # Provider errors are not proof of payment failure.
                continue

            if state == "paid":
                if not provider_payment:
                    continue

                outcome, confirmed_payment = confirm_razorpay_payment(
                    order_id=payment_probe["razorpay_order_id"],
                    payment_id=provider_payment["id"],
                    booking_id=booking_id,
                    amount_paise=provider_payment["amount"],
                )

                if (
                    outcome == "refund_required"
                    and confirmed_payment is not None
                ):
                    refund_payment(confirmed_payment.pk)

                # Confirmation/refund workflow owns this booking now.
                continue

            if state != "safe_to_release":
                # Pending or unknown: keep the reservation.
                continue

        with transaction.atomic():
            booking, slot = lock_slot_and_booking(booking_id)

            if (
                booking is None
                or booking.status != Bookings.AWAITING_PAYMENT
                or not booking.reservation_expired()
            ):
                continue

            # Lock and recheck the relevant transaction before changing it.
            payment = None

            if payment_probe:
                payment = (
                    Transaction.objects.select_for_update()
                    .filter(
                        pk=payment_probe["pk"],
                        booking_id=booking_id,
                    )
                    .first()
                )

                if payment is None:
                    continue

                if payment.status != "pending":
                    # Do not overwrite a concurrently completed/failed payment.
                    continue

                # Verify the order ID hasn't changed since the probe.
                if (
                    payment.razorpay_order_id
                    != payment_probe["razorpay_order_id"]
                ):
                    continue

            has_completed_payment = Transaction.objects.filter(
                booking=booking,
                status="completed",
            ).exists()

            if has_completed_payment:
                continue

            # Only expire after the provider has established safe-to-release,
            # or when no Razorpay order exists.
            booking.status = Bookings.EXPIRED
            booking.save(update_fields=["status"])

            if payment is not None:
                payment.status = "failed"
                payment.save(update_fields=["status", "updated_at"])

            another_active = Bookings.objects.filter(
                slots=slot,
                status__in=Bookings.ACTIVE_STATUSES,
            ).exclude(pk=booking.pk).exists()

            if not another_active:
                slot.is_booked = False
                slot.save(update_fields=["is_booked"])

            released += 1

    return released







def inspect_razorpay_order(order_id):
    """
    Return:
      ("paid", payment)       - a captured payment exists
      ("safe_to_release", None) - no attempt, or all attempts failed
      ("pending", None)       - an attempt may still succeed
      ("unknown", None)       - provider could not be checked

    Never release a slot when the provider result is unknown.
    """
    try:
        client = razorpay_client()

        order = client.order.fetch(order_id)
        payments_response = client.order.payments(order_id)
        payments = payments_response.get("items", [])

        # A captured payment must be processed through the normal,
        # idempotent booking confirmation function.
        captured = next(
            (p for p in payments if p.get("status") == "captured"),
            None,
        )
        if captured:
            return "paid", captured

        # An order with no attempts has no payment in progress.
        if order.get("status") == "created" and not payments:
            return "safe_to_release", None
        if payments and all(
            p.get("status") == "failed"
            for p in payments
        ):
            return "safe_to_release", None

        return "pending", None

    except Exception:
        logger.exception(
            "Could not reconcile Razorpay order %s", order_id
        )
        return "unknown", None


def cancel_checkout_reservation(booking_id, user):
    """
    Called after explicit Razorpay checkout dismissal.

    Returns:
      released | paid | already_finished | keep_reserved | not_found
    """
    probe = Bookings.objects.filter(
        pk=booking_id,
        user=user,
        payment_method="razorpay",
    ).values("pk", "status").first()

    if probe is None:
        return "not_found"

    if probe["status"] == Bookings.PENDING:
        return "paid"

    if probe["status"] != Bookings.AWAITING_PAYMENT:
        return "already_finished"

    payment_probe = Transaction.objects.filter(
        booking_id=booking_id,
    ).exclude(
        razorpay_order_id__isnull=True,
    ).exclude(
        razorpay_order_id="",
    ).order_by("-created_at").values(
        "pk", "razorpay_order_id"
    ).first()

    # Checkout should only be shown after an order exists. If it doesn't,
    # don't guess whether another request is currently creating it.
    if payment_probe is None:
        return "keep_reserved"

    state, provider_payment = inspect_razorpay_order(
        payment_probe["razorpay_order_id"]
    )

    if state == "paid":
        outcome, _ = confirm_razorpay_payment(
            order_id=payment_probe["razorpay_order_id"],
            payment_id=provider_payment["id"],
            user=user,
            booking_id=booking_id,
            amount_paise=provider_payment["amount"],
        )
        return "paid" if outcome in (
            "confirmed", "already_confirmed"
        ) else "keep_reserved"

    if state != "safe_to_release":
        return "keep_reserved"

    # Provider check is complete. Lock in the global order and recheck
    # local state before releasing the slot.
    with transaction.atomic():
        booking, slot = lock_slot_and_booking(
            booking_id,
            user_id=user.pk,
            payment_method="razorpay",
        )

        if booking is None:
            return "not_found"

        if booking.status == Bookings.PENDING:
            return "paid"

        if booking.status != Bookings.AWAITING_PAYMENT:
            return "already_finished"

        payment = Transaction.objects.select_for_update().filter(
            pk=payment_probe["pk"],
            booking=booking,
            razorpay_order_id=payment_probe["razorpay_order_id"],
        ).first()

        if payment is None or payment.status != "pending":
            return "keep_reserved"

        # Don't release a slot that has already started or is blocked.
        # The booking can still be expired; slot availability is governed
        # by the slot's own time/blocking rules.
        booking.status = Bookings.EXPIRED
        booking.save(update_fields=["status"])

        another_active = Bookings.objects.filter(
            slots=slot,
            status__in=Bookings.ACTIVE_STATUSES,
        ).exclude(pk=booking.pk).exists()

        if not another_active:
            slot.is_booked = False
            slot.save(update_fields=["is_booked"])

        return "released"






from decimal import Decimal

from django.db import transaction
from django.db.models import F
from django.utils import timezone


def cancel_appointment_service(
    booking_id,
    user,
    actor_type="patient",
):
    """
    Cancel a future appointment.

    Wallet:
        Refund the wallet inside one database transaction.
        Record the refund in WalletTransaction.
        Credit the existing wallet balance only once.

    Razorpay:
        Request/reconcile the provider refund outside the
        database transaction.
        Cancel the booking after refund confirmation.

    Lock order:
        Slot -> Booking -> Transaction/WalletTransaction -> Wallet
    """

    # Determine which bookings this user is allowed to cancel.
    if actor_type == "patient":
        filters = {"user": user}
    elif actor_type == "doctor":
        filters = {"doctor__user": user}
    else:
        return {"result": "not_found"}

    # ---------------------------------------------------------
    # PHASE 1: Lock slot and booking; validate cancellation.
    # ---------------------------------------------------------
    with transaction.atomic():
        booking, slot = lock_slot_and_booking(
            booking_id,
            **filters,
        )

        if booking is None:
            return {"result": "not_found"}

        if booking.status in (
            Bookings.CANCELLED,
            Bookings.EXPIRED,
        ):
            return {"result": "already_cancelled"}

        if slot.start_time <= timezone.now():
            return {
                "result": "not_eligible",
                "message": (
                    "You cannot cancel an appointment "
                    "that has already started."
                ),
            }

        # =====================================================
        # WALLET PAYMENT
        # =====================================================
        if booking.payment_method == "wallet":

            if booking.status != Bookings.PENDING:
                return {
                    "result": "not_eligible",
                    "message": (
                        "This wallet appointment cannot be "
                        "cancelled in its current state."
                    ),
                }

            # Lock the original completed wallet payment.
            wallet_payment = (
                WalletTransaction.objects
                .select_for_update()
                .filter(
                    booking=booking,
                    status="completed",
                    refund_idempotency_key__isnull=True,
                )
                .order_by("-created_at")
                .first()
            )

            if wallet_payment is None:
                logger.error(
                    "Cannot refund wallet booking %s: "
                    "original wallet payment not found.",
                    booking.pk,
                )

                return {
                    "result": "refund_failed",
                    "refund_status": "refund_failed",
                    "message": (
                        "We could not verify the wallet payment. "
                        "Please contact support before retrying."
                    ),
                }

            # Lock the user's existing wallet.
            wallet = (
                Wallet.objects
                .select_for_update()
                .filter(user_id=booking.user_id)
                .first()
            )

            if wallet is None:
                logger.error(
                    "Cannot refund wallet booking %s: "
                    "wallet not found.",
                    booking.pk,
                )

                return {
                    "result": "refund_failed",
                    "refund_status": "refund_failed",
                    "message": (
                        "Your wallet could not be found. "
                        "Please contact support."
                    ),
                }

            # Stable idempotency key: one refund per booking.
            refund_key = f"wallet-booking-{booking.pk}"

            # Create the refund ledger record.
            # The unique key prevents duplicate refund records.
            refund_transaction, refund_created = (
                WalletTransaction.objects.get_or_create(
                    refund_idempotency_key=refund_key,
                    defaults={
                        "wallet": wallet,
                        "user_id": booking.user_id,
                        "booking": booking,
                        "payment_id": (
                            f"wallet_refund_{booking.pk}"
                        ),
                        "currency": wallet_payment.currency,
                        "amount": wallet_payment.amount,
                        "status": "completed",
                    },
                )
            )

            # IMPORTANT:
            # Increase the EXISTING wallet balance only when
            # this refund record is created for the first time.
            if refund_created:
                Wallet.objects.filter(
                    pk=wallet.pk,
                ).update(
                    balance=F("balance") + wallet_payment.amount,
                    updated_at=timezone.now(),
                )

            # Mark the original payment as refunded.
            if wallet_payment.status != "refunded":
                wallet_payment.status = "refunded"
                wallet_payment.save(
                    update_fields=["status", "updated_at"]
                )

            # Cancel the booking in the same transaction.
            booking.status = Bookings.CANCELLED
            booking.save(update_fields=["status"])

            # Release the slot only if no other active booking
            # is using it.
            another_active = (
                Bookings.objects
                .filter(
                    slots=slot,
                    status__in=Bookings.ACTIVE_STATUSES,
                )
                .exclude(pk=booking.pk)
                .exists()
            )

            if not another_active:
                slot.is_booked = False
                slot.save(update_fields=["is_booked"])

            return {
                "result": "cancelled",
                "refund_status": "refunded",
                "refund_amount": str(refund_transaction.amount),
                "payment_method": "wallet",
            }

        # =====================================================
        # RAZORPAY PAYMENT
        # =====================================================
        payment = (
            Transaction.objects
            .select_for_update()
            .filter(booking=booking)
            .order_by("-created_at")
            .first()
        )

        paid_statuses = (
            "completed",
            "refund_pending",
            "refund_processing",
            "refunded",
            "refund_failed",
        )

        is_paid_razorpay = (
            booking.payment_method == "razorpay"
            and payment is not None
            and payment.status in paid_statuses
        )

        if is_paid_razorpay:

            if booking.status != Bookings.PENDING:
                return {
                    "result": "not_eligible",
                    "message": (
                        "This appointment cannot be cancelled "
                        "in its current state."
                    ),
                }

            payment_pk = payment.pk

        else:
            # Only an unpaid reservation without a Razorpay
            # order can be expired immediately.
            if (
                booking.payment_method != "razorpay"
                or booking.status != Bookings.AWAITING_PAYMENT
            ):
                return {
                    "result": "not_eligible",
                    "message": (
                        "This appointment cannot be cancelled "
                        "in its current state."
                    ),
                }

            if payment and payment.razorpay_order_id:
                return {
                    "result": "payment_pending",
                    "message": (
                        "Payment must be reconciled before "
                        "this reservation can be cancelled."
                    ),
                }

            booking.status = Bookings.EXPIRED
            booking.save(update_fields=["status"])

            another_active = (
                Bookings.objects
                .filter(
                    slots=slot,
                    status__in=Bookings.ACTIVE_STATUSES,
                )
                .exclude(pk=booking.pk)
                .exists()
            )

            if not another_active:
                slot.is_booked = False
                slot.save(update_fields=["is_booked"])

            return {
                "result": "cancelled",
                "refund_status": None,
                "payment_method": "razorpay",
            }

    # ---------------------------------------------------------
    # PHASE 2: Process Razorpay refund OUTSIDE atomic().
    # ---------------------------------------------------------
    refund_status = refund_payment(payment_pk)

    if refund_status in ("failed", "refund_failed"):
        return {
            "result": "refund_failed",
            "refund_status": "refund_failed",
            "message": (
                "We could not complete your refund automatically. "
                "Your appointment has not been cancelled. "
                "Please contact support for assistance."
            ),
        }

    if refund_status != "refunded":
        return {
            "result": "payment_pending",
            "refund_status": refund_status,
            "message": (
                "Your refund is being processed. "
                "The appointment will be cancelled after "
                "the refund is confirmed."
            ),
        }

    # ---------------------------------------------------------
    # PHASE 3: Confirm refund and finalize cancellation.
    # ---------------------------------------------------------
    with transaction.atomic():
        booking, slot = lock_slot_and_booking(
            booking_id,
            **filters,
        )

        if booking is None:
            return {"result": "not_found"}

        if booking.status in (
            Bookings.CANCELLED,
            Bookings.EXPIRED,
        ):
            return {"result": "already_cancelled"}

        if booking.status != Bookings.PENDING:
            return {
                "result": "not_eligible",
                "message": (
                    "The appointment status changed while "
                    "the refund was processing. Please contact support."
                ),
            }

        payment = (
            Transaction.objects
            .select_for_update()
            .filter(booking=booking)
            .order_by("-created_at")
            .first()
        )

        if not payment or payment.status != "refunded":
            return {
                "result": "payment_pending",
                "refund_status": payment.status if payment else None,
                "message": "Refund confirmation is required.",
            }

        booking.status = Bookings.CANCELLED
        booking.save(update_fields=["status"])

        if slot.start_time > timezone.now():
            another_active = (
                Bookings.objects
                .filter(
                    slots=slot,
                    status__in=Bookings.ACTIVE_STATUSES,
                )
                .exclude(pk=booking.pk)
                .exists()
            )

            if not another_active:
                slot.is_booked = False
                slot.save(update_fields=["is_booked"])

        return {
            "result": "cancelled",
            "refund_status": "refunded",
            "refund_amount": str(payment.amount),
            "payment_method": "razorpay",
        }



from decimal import Decimal
from django.db import transaction

from Users.models import Wallet, WalletTopUp


def confirm_wallet_topup(
    *,
    order_id,
    payment_id,
    amount_paise,
    payment_status,
    payment_currency,
    user=None,
):
    if not order_id or not payment_id:
        return "invalid_payment"

    try:
        amount_paise = int(amount_paise)
    except (TypeError, ValueError):
        return "invalid_payment"

    if amount_paise <= 0:
        return "invalid_payment"

    if payment_status != "captured" or payment_currency != "INR":
        return "payment_not_captured"

    with transaction.atomic():
        try:
            topup = (
                WalletTopUp.objects
                .select_for_update()
                .get(razorpay_order_id=order_id)
            )
        except WalletTopUp.DoesNotExist:
            return "not_found"

        # Callback requests must belong to the authenticated patient.
        if user is not None and topup.wallet.user_id != user.pk:
            return "not_found"

        # Verify the payment amount against the stored top-up amount.
        if amount_paise != to_paise(topup.amount):
            return "amount_mismatch"

        # Do not credit an already successful top-up twice.
        if topup.status == WalletTopUp.Status.SUCCESS:
            if topup.razorpay_payment_id == payment_id:
                return "already_confirmed"
            return "payment_mismatch"

        # Prevent reusing a payment ID for a different top-up.
        if WalletTopUp.objects.filter(
            razorpay_payment_id=payment_id
        ).exclude(pk=topup.pk).exists():
            return "payment_already_used"

        wallet = (
            Wallet.objects
            .select_for_update()
            .get(pk=topup.wallet_id)
        )

        wallet.balance = Decimal(wallet.balance) + Decimal(topup.amount)
        wallet.save(update_fields=["balance"])

        topup.razorpay_payment_id = payment_id
        topup.status = WalletTopUp.Status.SUCCESS
        topup.save(
            update_fields=[
                "razorpay_payment_id",
                "status",
                "updated_at",
            ]
        )

    return "confirmed"




MAX_WALLET_TOPUP_AMOUNT = Decimal("50000.00")


def create_wallet_topup_order(*, user, amount):
    """
    Create a wallet top-up record and a Razorpay order.
    This function does NOT credit the wallet balance.
    """

    # 1. Validate the amount received from the frontend.
    try:
        amount = Decimal(str(amount))
    except (InvalidOperation, TypeError, ValueError):
        raise BookingError(
            "Enter a valid top-up amount.",
            400,
            "invalid_amount",
        )

    if not amount.is_finite() or amount <= Decimal("0"):
        raise BookingError(
            "Top-up amount must be greater than zero.",
            400,
            "invalid_amount",
        )

    if amount > MAX_WALLET_TOPUP_AMOUNT:
        raise BookingError(
            "Maximum wallet top-up amount is ₹50,000.",
            400,
            "amount_limit_exceeded",
        )

    if amount != amount.quantize(Decimal("0.01")):
        raise BookingError(
            "Amount can have at most two decimal places.",
            400,
            "invalid_amount",
        )

    # 2. Create/get the patient's wallet and create the top-up.
    with transaction.atomic():
        wallet, _ = Wallet.objects.get_or_create(user=user)

        topup = WalletTopUp.objects.create(
            wallet=wallet,
            amount=amount,
            status=WalletTopUp.Status.CREATED,
        )

    # 3. Ask Razorpay to create the payment order.
    try:
        client = razorpay_client()

        order = client.order.create(
            data={
                "amount": to_paise(topup.amount),
                "currency": "INR",
                "receipt": f"wt_{topup.pk.hex}",
                "notes": {
                    "purpose": "wallet_topup",
                    "topup_id": str(topup.pk),
                    "user_id": str(user.pk),
                },
            }
        )

        # 4. Save the order ID so payment can be matched later.
        topup.razorpay_order_id = order["id"]
        topup.status = WalletTopUp.Status.PENDING
        topup.save(
            update_fields=[
                "razorpay_order_id",
                "status",
                "updated_at",
            ]
        )

    except Exception as exc:
        logger.exception(
            "Razorpay order creation failed for top-up %s",
            topup.pk,
        )

        topup.status = WalletTopUp.Status.FAILED
        topup.save(update_fields=["status", "updated_at"])

        raise BookingError(
            "Unable to create a payment order. Please retry.",
            502,
            "gateway_error",
        ) from exc

    # 5. Return the values the frontend needs for Razorpay Checkout.
    return {
        "topup_id": str(topup.pk),
        "order_id": topup.razorpay_order_id,
        "key_id": settings.RAZORPAY_KEY_ID,
        "amount": str(topup.amount),
        "amount_paise": to_paise(topup.amount),
        "currency": "INR",
    }