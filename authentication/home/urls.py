"""
URL configuration for authentication project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.urls import path
from .views import UserRegistrationView,UserLoginView,UserProfileView,Userchangepassword,SendPasswordReset,Userresetlinkverify


urlpatterns = [
 path('register/',UserRegistrationView.as_view(),name='register'),
 path('login/',UserLoginView.as_view(),name='login'),
 path('profile/',UserProfileView.as_view(),name='profile'),
 path('change/',Userchangepassword.as_view(),name="changepassword"),
 path('reset/',SendPasswordReset.as_view(),name='sendresetpassword'),
 path('reset/<uid>/<token>/',Userresetlinkverify.as_view(),name='resetverification')
]
