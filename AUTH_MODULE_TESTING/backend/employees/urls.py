from django.urls import path, include
from rest_framework.routers import DefaultRouter
from employees.views import (
    LoginView,
    DepartmentViewSet,
    EmployeeViewSet,
    DashboardStatsView,
    ActivityLogViewSet,
)

router = DefaultRouter()
router.register(r'departments', DepartmentViewSet, basename='department')
router.register(r'employees', EmployeeViewSet, basename='employee')
router.register(r'logs', ActivityLogViewSet, basename='activity-log')

urlpatterns = [
    path('auth/login/', LoginView.as_view(), name='login'),
    path('dashboard/stats/', DashboardStatsView.as_view(), name='dashboard-stats'),
    path('', include(router.urls)),
]
