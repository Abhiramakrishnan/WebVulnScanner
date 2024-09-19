from django.urls import path
from .views import scan

urlpatterns = [
    path('', scan, name='scan'),
]
