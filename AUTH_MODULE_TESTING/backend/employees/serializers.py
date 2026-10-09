from rest_framework import serializers
from django.contrib.auth.models import User
from employees.models import Department, Employee, ActivityLog


class DepartmentSerializer(serializers.ModelSerializer):
    employee_count = serializers.SerializerMethodField()

    class Meta:
        model = Department
        fields = ['id', 'name', 'code', 'description', 'created_at', 'employee_count']

    def get_employee_count(self, obj):
        return obj.employees.count()


class EmployeeSerializer(serializers.ModelSerializer):
    department_name = serializers.CharField(source='department.name', read_only=True)
    department_code = serializers.CharField(source='department.code', read_only=True)
    full_name = serializers.ReadOnlyField()

    class Meta:
        model = Employee
        fields = [
            'id', 'employee_id', 'first_name', 'last_name', 'full_name',
            'email', 'phone', 'department', 'department_name', 'department_code',
            'role', 'designation', 'salary', 'date_of_joining', 'status',
            'created_at', 'updated_at'
        ]


class ActivityLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ActivityLog
        fields = ['id', 'actor_username', 'action', 'details', 'ip_address', 'timestamp']


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
