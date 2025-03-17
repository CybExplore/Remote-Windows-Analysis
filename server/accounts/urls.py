# Import django
from django.urls import path, include

# Import rest_framework
from rest_framework import routers

# Import accounts
from accounts import views
from rest_framework.authtoken import views as rest_views


router = routers.DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'groups', views.GroupViewSet)

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    path('api/', include((router.urls, 'accounts'), namespace='accounts')),
    path('api/password-change/', views.PasswordChangeView.as_view(), name='password_change'),
    
    path('users/', views.UserList.as_view()),
    path('users/<pk>/', views.UserDetails.as_view()),
    path('groups/',views. GroupList.as_view()),
]

