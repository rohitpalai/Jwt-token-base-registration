from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializer import UserRegistrationSerializer,UserloginSerializer,UserprofileSerializer,UserChangepasswordSerializer,sendPasswordResetSerializer,UserResetVerifySerializer
from django.contrib.auth import authenticate
from .renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
# Create your views here.-------------------------------------------------------------------------
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
#----------------------------------------------------------------------------------------------------
class UserRegistrationView(APIView):
    renderer_classes=[UserRenderer]
    def post(self,request,formate=None):
        serializer=UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user=serializer.save()
            token=get_tokens_for_user(user)
            return Response({'token':token,'msg':"Registration Successful"},status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
#------------------------------------------------------------------------------------------------------------
class UserLoginView(APIView):
    renderer_classes=[UserRenderer]
    def post(self,request,format=None):
        serializer=UserloginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
         email=serializer.data.get('email')
         password=serializer.data.get('password')
        user=authenticate(email=email,password=password)
        if user is not None:
          token=get_tokens_for_user(user)
          return Response({'token':token,'msg':'login Success'},status=status.HTTP_200_OK)
        else:
            return Response({'errors':{'non_field_errors':['Email or Password is not valid']}},status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
#----------------------------------------------------------------------------------------------------------------
class UserProfileView(APIView):
   renderer_classes=[UserRenderer]
   permission_classes=[IsAuthenticated]
   def get(self,request,format=None):
      serializer=UserprofileSerializer(request.user)
      
      return Response(serializer.data,status=status.HTTP_200_OK)
#--------------------------------------------------------------------------------------------------------------
class Userchangepassword(APIView):
   renderer_classes=[UserRenderer]
   permission_classes=[IsAuthenticated]
   def post(self,request,format=None):
      serializer=UserChangepasswordSerializer(data=request.data,context={'user':request.user})
      if serializer.is_valid(raise_exception=True):
         return Response({'msg':'password is Successfully Changed'},status=status.HTTP_200_OK)
      else:
         return Response(serializer.errors,status=status.HTTP_404_NOT_FOUND)
      
#------------------------------------------------------------------------------------------------------------
class SendPasswordReset(APIView):
   renderer_classes=[UserRenderer]
   def post(self,request,format=None):
      serializer=sendPasswordResetSerializer(data=request.data)
      if serializer.is_valid(raise_exception=True):
         return Response({'massage':"Password reset link send on your Email"},status=status.HTTP_200_OK)
      else:
         return Response(serializer.errors,status=status.HTTP_404_NOT_FOUND)
      


#------------------------------------------------------------------------------------------------------------------
class Userresetlinkverify(APIView):
   renderer_classes=[UserRenderer]
   def post(self,request,uid,token,format=None):
      serilizer=UserResetVerifySerializer(data=request.data,context={'uid':uid,'token':token})
      if serilizer.is_valid(raise_exception=True):
         return Response({'massage':'password reset link work successfuly'},status=status.HTTP_200_OK)
      else:
         return Response(serilizer.errors,status=status.HTTP_400_BAD_REQUEST)
      