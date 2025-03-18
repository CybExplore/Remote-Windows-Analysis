# Import django
from django.urls import path, include # type: ignore

# Import rest_framework
from rest_framework import routers # type: ignore

# Import accounts
from accounts import views
from rest_framework.authtoken import views as rest_views # type: ignore


router = routers.DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'groups', views.GroupViewSet)

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    path('', include((router.urls, 'accounts'), namespace='accounts')),
    path('password-change/', views.PasswordChangeView.as_view(), name='password_change'),
    
    path('create-user/', views.CustomUserCreateView.as_view(), name='user-create'),
    path('users/<str:sid>/', views.CustomUserDetailView.as_view(), name='user-detail'),
    path('server-info/', views.ServerInfoView.as_view(), name='server-info'),

    # path('users/', views.UserList.as_view()),
    # path('users/<pk>/', views.UserDetails.as_view()),
    # path('groups/',views. GroupList.as_view()),
]

