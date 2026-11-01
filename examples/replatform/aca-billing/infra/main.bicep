param appName string = 'billing'
param location string = resourceGroup().location
var image = 'myacr.azurecr.io/billing:1.0'

resource env 'Microsoft.App/managedEnvironments@2023-05-01' existing = {
  name: 'env'
}

resource app 'Microsoft.App/containerApps@2023-05-01' = {
  name: appName
  location: location
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      ingress: {
        external: false
        targetPort: 8080
      }
      secrets: [
        {
          name: 'api-key'
          value: apiKey
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'billing'
          image: image
          env: [
            {
              name: 'API_KEY'
              secretRef: 'api-key'
            }
            {
              name: 'REGION'
              value: location
            }
          ]
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
        }
      ]
    }
  }
}

resource job 'Microsoft.App/jobs@2023-05-01' = {
  name: '${appName}-nightly'
  properties: {
    configuration: {
      triggerType: 'Schedule'
      scheduleTriggerConfig: { cronExpression: '0 3 * * *' }
    }
    template: { containers: [ { name: 'nightly', image: image, args: [ '--nightly' ] } ] }
  }
}
