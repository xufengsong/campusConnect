# api/urls.py
from django.urls import path
from django.urls import re_path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login_view'),
    path('logout/', views.logout_view, name='logout_view'),
    path('register/', views.register, name='register'),
    path('user_profile_view/', views.user_profile_view, name='user_profile_view'),
    path('get-csrf-token/', views.get_csrf_token, name='get-csrf-token'),
    path('get-ws-token/', views.get_ws_token, name='get_ws_token'),

    path('create_project/', views.create_project, name='create_new_project'),

    # Subscription and Payment URLs
    path('subscription-tiers/', views.get_subscription_tiers, name='get_subscription_tiers'),
    path('create-paypal-order/', views.create_paypal_order, name='create_paypal_order'),
    path('capture-paypal-payment/', views.capture_paypal_payment, name='capture_paypal_payment'),
    
    # PayPal return URLs (for frontend routing)
    path('payment/success/', views.payment_success_view, name='payment_success'),
    path('payment/cancel/', views.payment_cancel_view, name='payment_cancel'),

    # Timetable URLs
    path('timetable/', views.get_timetable, name='get_timetable'),
    path('timetable/add/', views.add_course, name='add_course'),
    path('timetable/update/<int:course_id>/', views.update_course, name='update_course'),
    path('timetable/delete/<int:course_id>/', views.delete_course, name='delete_course'),

    # Community Feed URLs
    path('posts/', views.get_posts, name='get_posts'),
    path('posts/create/', views.create_post, name='create_post'),
    path('posts/<int:post_id>/like/', views.like_post, name='like_post'),
    path('posts/<int:post_id>/delete/', views.delete_post, name='delete_post'),
]


