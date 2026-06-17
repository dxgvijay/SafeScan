from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import CustomUser


@receiver(post_save, sender=CustomUser)
def handle_new_user(sender, instance, created, **kwargs):
    if created:
        pass
