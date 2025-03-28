# Generated by Django 5.1.7 on 2025-03-18 05:28

import django.contrib.auth.models
import django.core.validators
import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='CustomUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('password_changed', models.BooleanField(default=False, help_text='Has the user changed their password?')),
                ('full_name', models.CharField(blank=True, help_text='Full name of the user', max_length=255, null=True)),
                ('email', models.EmailField(db_index=True, help_text="User's email address (required for credentials delivery)", max_length=254, unique=True)),
                ('sid', models.CharField(db_index=True, help_text='Security Identifier (SID) from Windows', max_length=50, unique=True, validators=[django.core.validators.RegexValidator(message='Invalid SID format. Must match Windows SID pattern (e.g., S-1-5-21-<domain>-<RID>).', regex='^S-1-5-21-\\d+-\\d+-\\d+-\\d+$')])),
                ('sid_type', models.CharField(blank=True, help_text="Type of SID (e.g., '1' for User)", max_length=10, null=True)),
                ('domain', models.CharField(blank=True, help_text='Domain of the user account', max_length=255, null=True)),
                ('local_account', models.BooleanField(default=False, help_text='Is this a local account?')),
                ('is_shutting_down', models.BooleanField(default=False, help_text='Was the system shutting down during account creation?')),
                ('account_type', models.CharField(blank=True, help_text="Account type (e.g., '512' for Normal)", max_length=50, null=True)),
                ('status', models.CharField(blank=True, help_text="Account status (e.g., 'OK', 'Degraded')", max_length=50, null=True)),
                ('caption', models.CharField(blank=True, help_text='Caption from Win32_UserAccount', max_length=255, null=True)),
                ('description', models.TextField(blank=True, help_text='Description of the user account', null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, help_text='When the account was created')),
                ('updated_at', models.DateTimeField(auto_now=True, help_text='When the account was last updated')),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
                'abstract': False,
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image', models.ImageField(blank=True, default='profile/default.png', help_text='Profile image for the user', null=True, upload_to='profile/')),
                ('account_expires', models.DateTimeField(blank=True, help_text='Date the account expires (AD: accountExpires)', null=True)),
                ('enabled', models.BooleanField(default=True, help_text='Is the account enabled? (Local: Enabled, AD: userAccountControl)')),
                ('password_changeable_date', models.DateTimeField(blank=True, help_text='When the password can next be changed (calculated from policy)', null=True)),
                ('password_expires', models.DateTimeField(blank=True, help_text='When the password expires (Local: PasswordExpires)', null=True)),
                ('user_may_change_password', models.BooleanField(default=True, help_text='Can the user change their password? (AD: userAccountControl)')),
                ('password_required', models.BooleanField(default=True, help_text='Is a password required? (Local: PasswordRequired)')),
                ('password_last_set', models.DateTimeField(blank=True, help_text='Last password set (Local: PasswordLastSet, AD: pwdLastSet)', null=True)),
                ('last_logon', models.DateTimeField(blank=True, help_text='Last logon time (Local: LastLogon, AD: lastLogon)', null=True)),
                ('principal_source', models.CharField(blank=True, help_text="Source of account (e.g., 'Local', 'ActiveDirectory')", max_length=50, null=True)),
                ('object_class', models.CharField(blank=True, help_text="Object class (e.g., 'User' from AD: objectClass)", max_length=50, null=True)),
                ('time_zone', models.CharField(blank=True, help_text="User's time zone (e.g., 'UTC', 'America/New_York')", max_length=50, null=True)),
                ('preferences', models.JSONField(blank=True, default=dict, help_text="User-specific settings (e.g., {'theme': 'dark'})", null=True)),
                ('last_login_ip', models.GenericIPAddressField(blank=True, help_text='IP address of last login', null=True)),
                ('last_password_change', models.DateTimeField(blank=True, help_text='Date of last password change in Windows', null=True)),
                ('logon_count', models.IntegerField(default=0, help_text='Number of logons tracked by the system')),
                ('locked_out', models.BooleanField(default=False, help_text='Is the account currently locked out?')),
                ('lockout_time', models.DateTimeField(blank=True, help_text='Timestamp of last lockout', null=True)),
                ('department', models.CharField(blank=True, help_text="User's department (AD: department)", max_length=100, null=True)),
                ('job_title', models.CharField(blank=True, help_text="User's job title (AD: title)", max_length=100, null=True)),
                ('local_groups', models.JSONField(blank=True, default=list, help_text="Local group memberships (e.g., ['Administrators', 'Users'])", null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
