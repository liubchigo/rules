using System;
using System.Threading.Tasks;
using Polly;
using SecurePipelineScan.VstsService;
using SecurePipelineScan.VstsService.Permissions;
using SecurePipelineScan.VstsService.Requests;
using Shouldly;
using Xunit;
using Permissions = AzureDevOps.Compliance.Rules.PermissionBits.Repository;

namespace AzureDevOps.Compliance.Rules.Tests.Integration
{
    public class NobodyCanBypassPoliciesTests : IClassFixture<TestConfig>
    {
        private readonly TestConfig _config;

        public NobodyCanBypassPoliciesTests(TestConfig config)
        {
            _config = config;
        }

        [Fact]
        [Trait("category", "integration")]
        public async Task ReconcileIntegrationTest()
        {
            var repositoryId = "88e64988-9e9e-41f2-a8b8-bfd25cae6688";
            var client = new VstsRestClient(_config.Organization, _config.Token);
            var projectId = (await client.GetAsync(Project.Properties(_config.Project))).Id;

            await ManagePermissions
                .ForRepository(client, projectId, repositoryId)
                .Permissions(Permissions.BypassPoliciesPullRequest)
                .SetToAsync(PermissionId.Allow);

            var rule = new NobodyCanBypassPolicies(client);
            (await rule.EvaluateAsync(projectId, repositoryId))
                .ShouldBe(false);
            await rule.ReconcileAsync(projectId, repositoryId);
            await Policy
                .Handle<Exception>()
                .WaitAndRetryAsync(Constants.NumRetries, t => TimeSpan.FromSeconds(t))
                .ExecuteAsync(async () =>
            {
                    (await rule.EvaluateAsync(projectId, repositoryId)).ShouldBe(true);
            });
        }

        [Fact]
        [Trait("category", "integration")]
        public async Task ReconcileIntegrationTestForMasterBranchPermission()
        {
            var repositoryId = "88e64988-9e9e-41f2-a8b8-bfd25cae6688";
            var client = new VstsRestClient(_config.Organization, _config.Token);
            var projectId = (await client.GetAsync(Project.Properties(_config.Project))).Id;

            await ManagePermissions
                .ForMasterBranch(client, projectId, repositoryId)
                .Permissions(Permissions.BypassPoliciesPullRequest)
                .SetToAsync(PermissionId.Allow);

            var rule = new NobodyCanBypassPolicies(client);
            (await rule.EvaluateAsync(projectId, repositoryId))
                .ShouldBe(false);
            await rule.ReconcileAsync(projectId, repositoryId);
            await Policy
                .Handle<Exception>()
                .WaitAndRetryAsync(Constants.NumRetries, t => TimeSpan.FromSeconds(t))
                .ExecuteAsync(async () =>
            {
                    (await rule.EvaluateAsync(projectId, repositoryId)).ShouldBe(true);
            });
        }
    }
}