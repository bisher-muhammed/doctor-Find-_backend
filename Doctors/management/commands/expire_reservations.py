from django.core.management.base import BaseCommand
from Doctors.booking_service import cleanup_outdated_slots, expire_stale_reservations, retry_pending_refunds


class Command(BaseCommand):
    help = "Release unpaid slot holds whose 15 minutes are up, and retry any failed refunds."

    def handle(self, *args, **options):
        released = expire_stale_reservations()
        refunded = retry_pending_refunds()
        deleted = cleanup_outdated_slots()
        self.stdout.write(f"released={released} refunds_retried_ok={refunded} outdated_slots_deleted={deleted}")

