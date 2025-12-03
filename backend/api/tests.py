from django.test import TestCase

# Create your tests here.
# your_app/tests/test_views.py

from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from unittest.mock import patch, MagicMock
from api.models import User, SubscriptionTier, PaymentTransaction, Vocabulary
import json

class AuthViewsTest(APITestCase):
    def test_register_success(self):
        """Ensure we can create a new user account."""
        url = reverse('register') # Make sure you have named your URL patterns
        data = {'username': 'newuser', 'email': 'new@example.com', 'password1': 'gghost12%^&', 'password2': 'gghost12%^&', 'motherLanguage': 'zh', 'targetLanguage': 'ko', 'fluencyLevel':'Upper Intermediate (B2)'}
        response = self.client.post(url, data, format='json')

        # FIX: Print the API's error message to debug.
        if response.status_code != 201:
            print("Registration failed. API response:", response.json())
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email='new@example.com').exists())
        # print("Succeed Register")

    def test_register_duplicate_email(self):
        """Ensure registration fails with a duplicate email."""
        User.objects.create_user(username='test', email='test@example.com', password='gghost12%^&')
        url = reverse('register')
        data = {'username': 'newuser', 'email': 'test@example.com', 'password1': 'gghost12%^&', 'password2': 'gghost12%^&', 'motherLanguage': 'zh', 'targetLanguage': 'ko', 'fluencyLevel':'Upper Intermediate (B2)'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_and_logout(self):
        """Test user login and logout."""
        user = User.objects.create_user(username='testuser', email='login@example.com', password='gghost12%^&')
        
        # Test Login
        login_url = reverse('login_view') # Assumes URL name is 'login_view'
        data = {'email': 'login@example.com', 'password': 'gghost12%^&'}
        response = self.client.post(login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Test Logout
        logout_url = reverse('logout_view')
        response = self.client.post(logout_url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class SubscriptionViewsTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='subuser', email='sub@example.com', password='pqgdfgafhareyasg')
        self.client.force_authenticate(user=self.user)
        self.free_tier = SubscriptionTier.objects.create(name='free', price=0, monthly_translation_limit=5, daily_translation_limit=1)
        self.premium_tier = SubscriptionTier.objects.create(name='premium', price=9.99, monthly_translation_limit=100, daily_translation_limit=10)

    @patch('uppercut_api.views.get_paypal_access_token')
    @patch('requests.post')
    def test_create_paypal_order_success(self, mock_requests_post, mock_get_token):
        """Ensure we can create a PayPal order."""
        # Mock external calls
        mock_get_token.return_value = 'FAKE_ACCESS_TOKEN'
        mock_requests_post.return_value = MagicMock(
            status_code=201, 
            json=lambda: {
                'id': 'PAYPAL_ORDER_ID',
                'links': [{'rel': 'approve', 'href': 'http://paypal.com/approve'}]
            }
        )

        url = reverse('create_paypal_order')
        data = {'tier_id': self.premium_tier.id}
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['order_id'], 'PAYPAL_ORDER_ID')
        self.assertTrue(PaymentTransaction.objects.filter(paypal_order_id='PAYPAL_ORDER_ID', status='pending').exists())
    
    @patch('uppercut_api.views.get_paypal_access_token')
    @patch('requests.post')
    def test_capture_paypal_payment_success(self, mock_requests_post, mock_get_token):
        """Test successful payment capture and subscription activation."""
        transaction = PaymentTransaction.objects.create(
            user=self.user,
            subscription_tier=self.premium_tier,
            paypal_order_id='ORDER_TO_CAPTURE',
            amount=9.99,
            status='pending'
        )
        # Mock external calls
        mock_get_token.return_value = 'FAKE_ACCESS_TOKEN'
        mock_requests_post.return_value = MagicMock(
            status_code=201,
            json=lambda: {'id': 'CAPTURE_ID', 'payer': {'payer_id': 'PAYER_ID'}}
        )

        url = reverse('capture_paypal_payment')
        data = {'order_id': 'ORDER_TO_CAPTURE'}
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify state changes
        self.user.refresh_from_db()
        transaction.refresh_from_db()

        self.assertEqual(self.user.subscription_tier, self.premium_tier)
        self.assertTrue(self.user.is_subscription_active)
        self.assertEqual(transaction.status, 'completed')

class CoreFunctionalityViewsTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='coreuser', email='core@example.com', password='pwmsgjwjsngnsaodigs')
        self.tier = SubscriptionTier.objects.create(name='free', price=0, monthly_translation_limit=1, daily_translation_limit=1)
        self.user.subscription_tier = self.tier
        self.user.save()
        self.client.force_authenticate(user=self.user)

    @patch('uppercut_api.views.callOpenAI_TranslationwContext')
    def test_analyze_content_within_limits(self, mock_openai_call):
        """Test content analysis when user is within their usage limits."""
        mock_openai_call.return_value = {"message": "Got content", "originalConent": "This is a test", "analysis": "mocked result"}
        
        url = reverse('analyze_content')
        data = {'content': 'This is a test.'}

        # This API call is supposed to increment the counter in the database.
        response = self.client.post(url, data, format='json')

        # FIX: Reload the user object from the database.
        self.user.refresh_from_db()

        # Now this assertion will check the updated value.
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.daily_translations_used, 1)
        self.assertEqual(self.user.monthly_translations_used, 1)



    @patch('uppercut_api.views.callOpenAI_TranslationwContext')
    def test_analyze_content_limit_reached(self, mock_openai_call):
        """
        Test content analysis fails with a specific error when the user has reached their daily limit.
        """
        url = reverse('analyze_content')
        
        # --- Step 1: Make a successful call to exhaust the daily limit (which is 1) ---
        # We need to mock the OpenAI call for this first request as well.
        mock_openai_call.return_value = {"message": "Mocked analysis for first call", "analysis": "first_result"}
        data_first_call = {'content': 'This is the first test content.'}
        
        response_first = self.client.post(url, data_first_call, format='json')
        self.assertEqual(response_first.status_code, status.HTTP_200_OK)
        
        # Reload user to ensure daily_translations_used is updated in the instance
        self.user.refresh_from_db()
        self.assertEqual(self.user.daily_translations_used, 1) # Verify daily limit is now reached
        self.assertEqual(self.user.monthly_translations_used, 1) # Verify monthly limit is now reached

        # Reset the mock for the second call. It shouldn't be called if the limit is hit.
        mock_openai_call.reset_mock() 

        # --- Step 2: Now, make the second call which should hit the limit ---
        data_second_call = {'content': 'This is the second test content, should be rejected.'}
        response_second = self.client.post(url, data_second_call, format='json')

        # We expect a "Too Many Requests" status code.
        self.assertEqual(response_second.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

        # We can also check if the response data contains our expected error message.
        # The message comes directly from user.can_translate()
        response_second_data = json.loads(response_second.content)
        self.assertIn("error", response_second_data)
        # The view now returns the specific message from can_translate()
        self.assertEqual(response_second_data["error"], "Daily analysis limit reached. Please upgrade or wait until tomorrow.") 

        # Ensure the underlying analysis function was not actually called on the second request
        # because the view should have checked the limit first and returned 429.
        mock_openai_call.assert_not_called()

    @patch('uppercut_api.views.callOpenAI_TranslationwContext') # Patch the function that will be called
    def test_analyze_content_invalid_json(self, mock_openai_call):
        """Test content analysis with invalid JSON in the request body."""
        url = reverse('analyze_content')
        # Send invalid JSON (e.g., missing a closing brace)
        invalid_json_data = "{'content': 'This is a test'" 
        response = self.client.post(url, invalid_json_data, content_type='application/json')
        response_data = json.loads(response.content)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response_data)
        self.assertEqual(response_data["error"], "Invalid JSON")

        mock_openai_call.assert_not_called() # Should not call OpenAI if JSON is bad

    @patch('uppercut_api.views.callOpenAI_TranslationwContext')
    def test_analyze_content_missing_content_field(self, mock_openai_call):
        """Test content analysis when the 'content' field is missing."""
        url = reverse('analyze_content')
        data = {'some_other_field': 'value'} # Missing 'content' key
        response = self.client.post(url, data, format='json')
        response_data = json.loads(response.content)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response_data)
        self.assertEqual(response_data["error"], "Content field is required.")

        mock_openai_call.assert_not_called() # Should not call OpenAI if content is missing

    @patch('uppercut_api.views.callOpenAI_TranslationwContext')
    def test_analyze_content_openai_api_error(self, mock_openai_call):
        """Test content analysis when the OpenAI API call fails."""
        # Configure the mock to raise an exception, simulating an OpenAI API error
        mock_openai_call.side_effect = Exception("OpenAI API call failed due to network issue.")
        
        url = reverse('analyze_content')
        data = {'content': 'This content will trigger an OpenAI error.'}
        
        response = self.client.post(url, data, format='json')
        response_data = json.loads(response.content)
        
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn("error", response_data)
        self.assertEqual(response_data["error"], "An error occured during Analysis process")

        mock_openai_call.assert_called_once() # Ensure it was called before failing

    def test_add_unknown_vocabs(self):
        """Test adding words to a user's unknown vocabulary list."""
        url = reverse('update_vocabulary')
        data = {
            "words": [{
                "baseForm": "test",
                "word": ["test"],
                "meaning": [{"pos": "noun", "def": "an examination"}]
            }]
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        vocab = Vocabulary.objects.get(baseForm='test')
        self.assertTrue(self.user.unknown_words.filter(id=vocab.id).exists())