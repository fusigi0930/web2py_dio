# -*- coding: utf-8 -*-
### required - do no delete

def user():
    #return dict(form=auth())
    auth.logout()
    redirect(URL('api', 'user/login')) 
def download(): 
    #return response.download(request,db)
    auth.logout()
    return dict(message='not support now')
def call(): 
    #return service()
    auth.logout()
    return dict(message='not support now')
### end requires
def index():
    #return dict()
    redirect(URL('api', 'user/login')) 

def error():
    #return dict()
    redirect(URL('api', 'user/login'))
