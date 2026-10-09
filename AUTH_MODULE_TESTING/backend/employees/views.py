from rest_framework import viewsets, status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.db.models import Count, Q
from employees.models import Department, Employee, ActivityLog
from employees.serializers import (
    DepartmentSerializer,
    EmployeeSerializer,
    ActivityLogSerializer,
    UserLoginSerializer,
)


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            user = authenticate(username=username, password=password)

            if user:
                ActivityLog.objects.create(
                    actor_username=user.username,
                    action="LOGIN_SUCCESS",
                    details=f"User {user.username} logged in successfully.",
                    ip_address=get_client_ip(request)
                )

                employee_profile = getattr(user, 'employee_profile', None)
                role = employee_profile.role if employee_profile else 'ADMIN'

                return Response({
                    "status": "success",
                    "message": "Login successful",
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "role": role,
                        "full_name": f"{user.first_name} {user.last_name}" or user.username
                    }
                }, status=status.HTTP_200_OK)

            ActivityLog.objects.create(
                actor_username=username,
                action="LOGIN_FAILED",
                details=f"Failed login attempt for username: {username}",
                ip_address=get_client_ip(request)
            )
            return Response({"status": "error", "message": "Invalid username or password"}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DepartmentViewSet(viewsets.ModelViewSet):
    queryset = Department.objects.all().order_by('name')
    serializer_class = DepartmentSerializer
    permission_classes = [AllowAny]


class EmployeeViewSet(viewsets.ModelViewSet):
    queryset = Employee.objects.all().order_by('-created_at')
    serializer_class = EmployeeSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        queryset = super().get_queryset()
        search = self.request.query_params.get('search', None)
        department_id = self.request.query_params.get('department', None)
        status_filter = self.request.query_params.get('status', None)

        if search:
            queryset = queryset.filter(
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search) |
                Q(email__icontains=search) |
                Q(employee_id__icontains=search) |
                Q(designation__icontains=search)
            )

        if department_id:
            queryset = queryset.filter(department_id=department_id)

        if status_filter:
            queryset = queryset.filter(status=status_filter)

        return queryset


class DashboardStatsView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        total_employees = Employee.objects.count()
        active_employees = Employee.objects.filter(status='ACTIVE').count()
        on_leave = Employee.objects.filter(status='ON_LEAVE').count()
        total_departments = Department.objects.count()

        dept_distribution = Department.objects.annotate(count=Count('employees')).values('name', 'code', 'count')

        return Response({
            "total_employees": total_employees,
            "active_employees": active_employees,
            "on_leave": on_leave,
            "total_departments": total_departments,
            "department_distribution": list(dept_distribution)
        }, status=status.HTTP_200_OK)


class ActivityLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ActivityLog.objects.all().order_by('-timestamp')[:50]
    serializer_class = ActivityLogSerializer
    permission_classes = [AllowAny]
