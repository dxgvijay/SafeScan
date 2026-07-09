from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import post_migrate
from django.dispatch import receiver
from django.conf import settings


ADMIN_PERMISSIONS = [
    'add_customuser', 'change_customuser', 'delete_customuser', 'view_customuser',
    'add_loginaudit', 'change_loginaudit', 'delete_loginaudit', 'view_loginaudit',
    'add_activitylog', 'change_activitylog', 'delete_activitylog', 'view_activitylog',
    'add_scanhistory', 'change_scanhistory', 'delete_scanhistory', 'view_scanhistory',
]

WORKER_PERMISSIONS = [
    'add_scanhistory', 'change_scanhistory', 'view_scanhistory',
    'view_customuser',
    'view_activitylog',
]


@receiver(post_migrate)
def create_default_groups(sender, **kwargs):
    if sender.label != 'accounts':
        return

    admin_group, _ = Group.objects.get_or_create(name='Admin')
    worker_group, _ = Group.objects.get_or_create(name='Worker')
    user_group, _ = Group.objects.get_or_create(name='User')

    ct_user = ContentType.objects.get(app_label='accounts', model='customuser')
    ct_audit = ContentType.objects.get(app_label='accounts', model='loginaudit')
    ct_activity = ContentType.objects.get(app_label='accounts', model='activitylog')
    ct_scan = ContentType.objects.get(app_label='accounts', model='scanhistory')

    admin_perms = Permission.objects.filter(
        content_type__in=[ct_user, ct_audit, ct_activity, ct_scan]
    )
    admin_group.permissions.set(admin_perms)

    worker_perms = Permission.objects.filter(
        codename__in=WORKER_PERMISSIONS
    )
    worker_group.permissions.set(worker_perms)

    user_group.permissions.clear()


def assign_role(user, role_name):
    from django.contrib.auth.models import Group
    try:
        group = Group.objects.get(name=role_name)
        user.groups.add(group)
    except Group.DoesNotExist:
        pass


def create_default_accounts():
    from django.contrib.auth import get_user_model
    User = get_user_model()

    defaults = [
        {
            'username': 'admin',
            'email': 'admin@cipherscan.local',
            'password': 'Admin@12345',
            'role': 'Admin',
            'is_staff': True,
            'is_superuser': True,
        },
        {
            'username': 'worker',
            'email': 'worker@cipherscan.local',
            'password': 'Worker@12345',
            'role': 'Worker',
            'is_staff': False,
            'is_superuser': False,
        },
    ]

    for data in defaults:
        username = data['username']
        if not User.objects.filter(username=username).exists() and not User.objects.filter(email=data['email']).exists():
            user = User.objects.create_user(
                username=username,
                email=data['email'],
                password=data['password'],
                is_staff=data['is_staff'],
                is_superuser=data['is_superuser'],
            )
            assign_role(user, data['role'])
