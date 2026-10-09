from django.db import models
from django.contrib.auth.models import User


class Department(models.Model):
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=20, unique=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.code})"


class Employee(models.Model):
    ROLE_CHOICES = (
        ('ADMIN', 'Admin'),
        ('MANAGER', 'Manager'),
        ('EMPLOYEE', 'Employee'),
    )

    STATUS_CHOICES = (
        ('ACTIVE', 'Active'),
        ('ON_LEAVE', 'On Leave'),
        ('TERMINATED', 'Terminated'),
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='employee_profile', null=True, blank=True)
    employee_id = models.CharField(max_length=20, unique=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True, related_name='employees')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='EMPLOYEE')
    designation = models.CharField(max_length=100)
    salary = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    date_of_joining = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name} [{self.employee_id}]"

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"


class ActivityLog(models.Model):
    actor_username = models.CharField(max_length=150)
    action = models.CharField(max_length=255)
    details = models.TextField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.timestamp}] {self.actor_username}: {self.action}"
