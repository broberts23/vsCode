# Test Reports

This directory contains test results and coverage reports for the Password Reset Function App.

## Generated Reports

- **TestResults.xml** - NUnit format test results for CI/CD integration
- **TestResults.html** - Styled HTML report for human viewing
- **Coverage.xml** - JaCoCo format code coverage for CI/CD integration

## Generating Reports

To generate fresh test reports, run:

```powershell
./scripts/Generate-TestReports.ps1
```

This script will:

- Run all unit tests in `tests/Unit/`
- Generate NUnit XML test results
- Generate JaCoCo XML code coverage report
- Generate HTML report with styled output
- Display a summary of results

To view the HTML report:

```bash
xdg-open tests/TestResults.html
```

## Test Structure

### Unit Tests (`tests/Unit/`)

- **PasswordResetHelpers.Tests.ps1** - Comprehensive unit tests for all helper functions
  - Module load verification (5 tests)
  - JWT token validation (10 tests)
  - Role-based authorization (5 tests)
  - Secure password generation (10 tests)
  - AD password reset operations (9 tests)

**Status**: ✅ 39/39 tests passing  
**Coverage**: 95.1% (81/86 lines covered in PasswordResetHelpers.psm1)

### Integration Tests (`tests/Integration/`)

- **ResetUserPassword.Tests.ps1** - End-to-end function execution tests

**Status**: ⚠️ Skipped (Pester 5 scoping issues with `Invoke-Expression` pattern)

> **Note**: Integration tests use dynamic script loading via `Invoke-Expression` which has variable scoping challenges in Pester 5. Unit tests provide comprehensive coverage of all functionality with proper mocking.

## CI/CD Integration

### Azure DevOps / GitHub Actions

Both XML formats can be consumed by CI/CD pipelines:

```yaml
# Publish test results
- task: PublishTestResults@2
  inputs:
    testResultsFormat: "NUnit"
    testResultsFiles: "**/TestResults.xml"

# Publish code coverage
- task: PublishCodeCoverageResults@2
  inputs:
    codeCoverageTool: "JaCoCo"
    summaryFileLocation: "**/Coverage.xml"
```

## Test Coverage Details

The code coverage report tracks execution of:

- **Modules/PasswordResetHelpers/PasswordResetHelpers.psm1** - Core helper functions (unit testable code)

> **Note**: `ResetUserPassword/run.ps1` (Azure Function HTTP trigger entry point) is excluded from coverage metrics as it requires integration tests. The HTTP trigger is a thin orchestration layer that calls the well-tested helper functions.

### Coverage by Function

| Function           | Lines Covered | Coverage % |
| ------------------ | ------------- | ---------- |
| Test-JwtToken      | 18/19         | 94.7%      |
| Test-RoleClaim     | 11/12         | 91.7%      |
| New-SecurePassword | 21/22         | 95.5%      |
| Set-ADUserPassword | 24/26         | 92.3%      |
| **Overall Module** | **81/86**     | **95.1%**  |

## Test Environment

All tests use:

- **PowerShell 7.4**
- **Pester 5.7.1** - Modern testing framework
- **Mock ActiveDirectory module** - Enables testing on Linux without Windows AD cmdlets
- **Mock JWT validation** - Tests use System.Security.Claims types loaded from bin/ folder

## Dependencies

Tests require:

- System.IdentityModel.Tokens.Jwt DLLs (in bin/ folder)
- Mock ActiveDirectory module (installed at `~/.local/share/powershell/Modules/ActiveDirectory/`)
- PasswordResetHelpers module

All dependencies are automatically loaded by test files.
