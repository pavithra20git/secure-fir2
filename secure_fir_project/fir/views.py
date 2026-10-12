from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods
from . import services

@require_http_methods(["GET","POST"])
def login_view(request):
    if request.user.is_authenticated: return redirect("dashboard")
    if request.method=="POST":
        user=authenticate(request,username=request.POST.get("username","").strip(),password=request.POST.get("password",""))
        if user and user.is_active:
            login(request,user); return redirect("dashboard")
        messages.error(request,"Invalid username or password.")
    return render(request,"fir/login.html")

@login_required
def logout_view(request):
    logout(request); return redirect("login")

@login_required
def dashboard(request):
    try: records=services.all_records(); error=""
    except Exception as e: records=[]; error=str(e)
    return render(request,"fir/dashboard.html",{"records":records,"db_error":error})

@login_required
@require_http_methods(["GET","POST"])
def create_fir(request):
    data={}; suggestions=[]
    if request.method=="POST":
        data={k:request.POST.get(k,"").strip() for k in ["complainant_name","incident_date","incident_location","complaint_text"]}
        if not all(data.values()): messages.error(request,"Complete all fields.")
        else:
            try:
                suggestions=services.suggest(data["complaint_text"])
                data["police_selected_provision"]=request.POST.get("selected_suggestion","").strip()
                data["nlp_suggestions"]=suggestions
                rec=services.create(data,request.user.username)
                messages.success(request,"FIR registered: "+rec["fir_id"])
                return redirect("detail",fir_id=rec["fir_id"])
            except Exception as e: messages.error(request,"Save failed. Check MongoDB/IPFS settings: "+str(e))
    return render(request,"fir/create.html",{"data":data,"suggestions":suggestions})

@login_required
def detail(request,fir_id):
    rec=services.get_record(fir_id)
    if not rec: messages.error(request,"FIR not found"); return redirect("dashboard")
    return render(request,"fir/detail.html",{"r":rec})

@login_required
@require_http_methods(["GET","POST"])
def verify(request,fir_id):
    rec=services.get_record(fir_id)
    if not rec: messages.error(request,"FIR not found"); return redirect("dashboard")
    result=None
    if request.method=="POST":
        try:
            ok,msg,payload=services.verify_record(fir_id); result={"ok":ok,"message":msg,"payload":payload}
        except Exception as e: result={"ok":False,"message":str(e),"payload":None}
    return render(request,"fir/verify.html",{"r":rec,"result":result})
