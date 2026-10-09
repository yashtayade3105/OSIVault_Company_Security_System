import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'employee_portal.settings')
django.setup()

from django.contrib.auth.models import User
from employees.models import Department, Employee, ActivityLog

def seed():
    print("Seeding database...")
    
    # 1. Create Superuser / Admin
    admin_user, created = User.objects.get_or_create(
        username="admin",
        defaults={
            "email": "admin@onesmarter.com",
            "first_name": "System",
            "last_name": "Admin",
            "is_staff": True,
            "is_superuser": True
        }
    )
    if created:
        admin_user.set_password("admin123")
        admin_user.save()
        print("Admin user created (username: admin, password: admin123)")

    # 2. Create Departments
    departments_data = [
        {"name": "Engineering & Technology", "code": "ENG", "description": "Core software architecture, API security, and platform engineering."},
        {"name": "Security & Audit", "code": "SEC", "description": "Lead security posture, HIPAA compliance, and WebAuthn MFA operations."},
        {"name": "Human Resources", "code": "HR", "description": "Talent management, onboarding, and employee relations."},
        {"name": "Finance & Payroll", "code": "FIN", "description": "Financial accounting, payroll processing, and claims settlement."},
    ]

    dept_objs = {}
    for data in departments_data:
        dept, _ = Department.objects.get_or_create(code=data["code"], defaults=data)
        dept_objs[data["code"]] = dept
    print(f"Created {len(dept_objs)} departments.")

    # 3. Create Sample Employees
    employees_data = [
        {
            "employee_id": "EMP-1001",
            "first_name": "Yash",
            "last_name": "Chavan",
            "email": "yash.chavan@onesmarter.com",
            "phone": "+1 (555) 019-2834",
            "department": dept_objs["SEC"],
            "role": "ADMIN",
            "designation": "Lead Security Engineer",
            "salary": 145000.00,
            "date_of_joining": "2024-01-15",
            "status": "ACTIVE"
        },
        {
            "employee_id": "EMP-1002",
            "first_name": "Vikram",
            "last_name": "Shete",
            "email": "vikram.shete@onesmarter.com",
            "phone": "+1 (555) 018-9922",
            "department": dept_objs["ENG"],
            "role": "ADMIN",
            "designation": "VP of Engineering",
            "salary": 185000.00,
            "date_of_joining": "2023-05-10",
            "status": "ACTIVE"
        },
        {
            "employee_id": "EMP-1003",
            "first_name": "Prajval",
            "last_name": "Kulkarni",
            "email": "prajval.k@onesmarter.com",
            "phone": "+1 (555) 017-3344",
            "department": dept_objs["ENG"],
            "role": "MANAGER",
            "designation": "Senior Fullstack Lead",
            "salary": 135000.00,
            "date_of_joining": "2024-03-01",
            "status": "ACTIVE"
        },
        {
            "employee_id": "EMP-1004",
            "first_name": "Rushikesh",
            "last_name": "Patil",
            "email": "rushi.patil@onesmarter.com",
            "phone": "+1 (555) 016-5566",
            "department": dept_objs["FIN"],
            "role": "MANAGER",
            "designation": "Finance Operations Manager",
            "salary": 125000.00,
            "date_of_joining": "2024-06-15",
            "status": "ACTIVE"
        },
        {
            "employee_id": "EMP-1005",
            "first_name": "Ananya",
            "last_name": "Sharma",
            "email": "ananya.sharma@onesmarter.com",
            "phone": "+1 (555) 015-7788",
            "department": dept_objs["HR"],
            "role": "EMPLOYEE",
            "designation": "HR Specialist",
            "salary": 85000.00,
            "date_of_joining": "2025-02-01",
            "status": "ACTIVE"
        },
    ]

    for emp_data in employees_data:
        Employee.objects.get_or_create(employee_id=emp_data["employee_id"], defaults=emp_data)
    print("Sample employees created successfully.")

    # 4. Activity Logs
    ActivityLog.objects.create(
        actor_username="admin",
        action="SYSTEM_INIT",
        details="Employee Management System platform initialized with seed data.",
        ip_address="127.0.0.1"
    )
    print("Seed process complete.")

if __name__ == "__main__":
    seed()
