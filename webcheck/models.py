from django.db import models

# Create your models here.
from django.db import models
from django import forms
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

class URLForm(forms.Form):
    url = forms.CharField(label = 'Enter URL  ', max_length=100)

