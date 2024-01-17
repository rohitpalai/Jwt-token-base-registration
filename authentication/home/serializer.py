from rest_framework import serializers
from .models import User
from xml.dom import ValidationErr
from  django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import utils
#-----------------------------------------------------------------------------------------------------------------
class UserRegistrationSerializer(serializers.ModelSerializer):
    password2=serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model=User
        fields=['email','name','password','password2','tc']
        extra_kwargs={
            'password':{'write_only':True}
        }



    def validate(self, attrs):
         password=attrs.get('password')
         password2=attrs.get('password2')
         if password!=password2:
             raise serializers.ValidationError("Both password are not same please check and Rewrite")
         return attrs
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
#---------------------------------------------------------------------------------------------------------------------
    

class UserloginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        model=User
        fields=['email','password']
#-------------------------------------------------------------------------------------------------------------------
class UserprofileSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['email','name','id']


#--------------------------------------------------------------------------------------------------------------
class UserChangepasswordSerializer(serializers.ModelSerializer):
   password=serializers.CharField(style={'input_type':'password'},write_only=True)
   password2=serializers.CharField(style={'input_type':'password'},write_only=True)
   class Meta:
       model=User
       fields=['password','password2']
   def validate(self, attrs):
         password=attrs.get('password')
         password2=attrs.get('password2')
         user=self.context.get('user')
         if password!=password2:
             raise serializers.ValidationError("Both password are not same please check and Rewrite")
         user.set_password(password)
         user.save()
         return attrs
#-----------------------------------------------------------------------------------------------------------------
class sendPasswordResetSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        model=User
        fields=['email']
    def validate(self,attrs):
        email=attrs.get('email')
        if User.objects.filter(email=email).exists:
            user=User.objects.get(email=email)
            uid=urlsafe_base64_encode(force_bytes(user.id))
            print('encode id',uid)
            token=PasswordResetTokenGenerator().make_token(user)
            print('password reset token thats through we can access',token)
            link='http://127.0.0.1:8000/reset/'+uid+'/'+token
            print('password reset link',link)
#------------------------------------its email send code-----------------------------------------
            data={
                'subject':'reset password',
                'body':"If you want to reset password click on this link otherwise dont click"+link,
                'to_email':user.email
            }
            utils.send_email(data)
            return attrs
        else:
            raise ValidationErr('you are not a Register,Please Register.')


#-----------------------------------------------------------------------------------------------------------------
class UserResetVerifySerializer(serializers.Serializer):
    password=serializers.CharField(style={'input_type':'password'},write_only=True)
    password2=serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        
       fields=['password','password2']
    def validate(self, attrs):
         try:
            password=attrs.get('password')
            password2=attrs.get('password2')
            uid=self.context.get('uid')
            token=self.context.get('token')
            if password!=password2:
                raise serializers.ValidationError("Both password are not same please check and Rewrite")
            id=smart_str(urlsafe_base64_decode(uid))

            user=User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise ValidationErr('Token is not valid')
            user.set_password(password)
            user.save()
            return attrs
         except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user,token)
            raise ValidationErr('Token is not valid')
         

#-------------------------------------------------------------------------------------------------------------------

                  
    
      
       
    