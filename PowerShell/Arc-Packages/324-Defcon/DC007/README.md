# DC007 Arc Package

This folder contains the current Arc telemetry execution package for machine DC007.

## Included
- Run-LabTelemetry-AllInOne.ps1
- Push-CloudUserSimulationViaArc.ps1
- Invoke-DailyCloudUserSimulation.ps1
- Register-DailyCloudUserSimulationTask.ps1
- New-CloudUserSimulationProfileSet.ps1
- Invoke-EnhancedLabTelemetry.ps1
- CloudUserSimulation.SampleConfig.json
- CloudUserSimulation.MngEnvUsers.csv

## Typical Arc Use
1. Use Push-CloudUserSimulationViaArc.ps1 to deploy package to the machine via Arc run command.
2. Optionally execute immediate run after deploy.
3. Optionally register remote daily task.
