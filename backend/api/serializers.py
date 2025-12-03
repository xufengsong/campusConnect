from rest_framework import serializers
from .models import User, Project, Timetable, ThreadPost

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # Define the fields you want to send to the frontend.
        # NEVER include the password hash.
        fields = [
            'id', 
            'email', 
            'name', 
            'username',
            'university',
            'country',
            'avatar',
        ]


class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        # List all the fields you want to send to the frontend
        fields = ['id', 'project_name', 'project_id', 'created_at', 'cognee_nodeset_name']


class TimetableSerializer(serializers.ModelSerializer):
    class Meta:
        model = Timetable
        fields = ['id', 'course_name', 'professor_name', 'location', 'day_of_week', 'start_time', 'duration', 'color']


class ThreadPostSerializer(serializers.ModelSerializer):
    author = UserSerializer(source='user', read_only=True)
    likes = serializers.IntegerField(source='likes_count', read_only=True)
    comments = serializers.IntegerField(source='comments_count', read_only=True)
    timestamp = serializers.DateTimeField(source='created_at', read_only=True, format="%Y-%m-%d %H:%M:%S")
    liked = serializers.SerializerMethodField()

    class Meta:
        model = ThreadPost
        fields = ['id', 'author', 'content', 'image', 'tags', 'likes', 'comments', 'liked', 'timestamp']

    def get_liked(self, obj):
        # Placeholder for now, as we don't have a Like model yet
        return False