from django.contrib import admin
from django.urls import path, include, reverse
from django.views.generic import RedirectView

from myapp import views

urlpatterns = [
    path('', views.index, name='index'),
    path("home/", RedirectView.as_view(pattern_name='index', permanent=False), name='home'),
    path("otp/verify/", views.verify_otp, name="verify_otp"),  # new
    path("protected/view/", views.protected_view, name="protected_view"),  # new
    path("input/module/", views.input_module, name="input_module"),  # new
]