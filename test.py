import glob
folder="upload/*"
for name in glob.glob(folder): 
    print("[Info] Uploading :",name) 