# 1) Bootstrap (hello-world)
.\script\Deploy-Infrastructure.ps1 -ResourceGroup <rg> -TenantId <tid> -ApiClientId <appId>
# 2) Build/push
.\script\Build-Push-Image.ps1 -AcrName <acrNameFromOutputs>
# 3) Real app image
.\script\Deploy-Infrastructure.ps1 -ResourceGroup <rg> -TenantId <tid> -ApiClientId <appId> `
  -ContainerImage <loginServer>/fastapi-swagger:dev