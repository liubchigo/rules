using System;
using AutoFixture;
using AutoFixture.AutoNSubstitute;
using Newtonsoft.Json.Linq;
using NSubstitute;
using SecurePipelineScan.Rules.Security;
using SecurePipelineScan.VstsService;
using SecurePipelineScan.VstsService.Requests;
using SecurePipelineScan.VstsService.Response;
using Shouldly;
using Xunit;
using Project = SecurePipelineScan.VstsService.Response.Project;
using Repository = SecurePipelineScan.VstsService.Response.Repository;
using Task = System.Threading.Tasks.Task;

namespace SecurePipelineScan.Rules.Tests.Security
{
    public class BuildPipelineHasCredScanTaskTests : IClassFixture<TestConfig>
    {
        private readonly TestConfig _config;
        private readonly Fixture _fixture = new Fixture {RepeatCount = 1};

        public BuildPipelineHasCredScanTaskTests(TestConfig config)
        {
            _config = config;
            _fixture.Customize(new AutoNSubstituteCustomization());
        }

        [Fact]
        [Trait("category", "integration")]
        public async Task EvaluateIntegrationTest_gui()
        {
            var client = new VstsRestClient(_config.Organization, _config.Token);
            var project = await client.GetAsync(VstsService.Requests.Project.ProjectById(_config.Project));
            var buildPipeline = await client.GetAsync(Builds.BuildDefinition(project.Id, "2"))
                .ConfigureAwait(false); // 'SOx-compliant-demo-ASP.NET Core-CI' pipeline

            var rule = new BuildPipelineHasCredScanTask(client);
            (await rule.EvaluateAsync(project, buildPipeline)).GetValueOrDefault().ShouldBeTrue();
        }

        [Fact]
        [Trait("category", "integration")]
        public async Task EvaluateIntegrationTest_yaml()
        {
            var client = new VstsRestClient(_config.Organization, _config.Token);
            var project = await client.GetAsync(VstsService.Requests.Project.ProjectById(_config.Project));
            var buildPipeline = await client.GetAsync(Builds.BuildDefinition(project.Id, "275"))
                .ConfigureAwait(false); // 'NestedYamlTemplates' pipeline

            var rule = new BuildPipelineHasCredScanTask(client);
            (await rule.EvaluateAsync(project, buildPipeline)).GetValueOrDefault().ShouldBeTrue();
        }

        [Fact]
        public void BuildPipelineHasCredScanTask_ShouldHaveCorrectProperties()
        {
            // Arrange
            var client = Substitute.For<IVstsRestClient>();
            var rule = new BuildPipelineHasCredScanTask(client);

            // Assert
            Assert.Equal("Build pipeline contains credential scan task", ((IRule) rule).Description);
            Assert.Equal("https://confluence.dev.somecompany.nl/x/LorHDQ", ((IRule) rule).Link);
            Assert.False(((IRule) rule).IsSox);
        }

        [Theory]
        [InlineData("f0462eae-4df1-45e9-a754-8184da95ed01", true)]
        [InlineData("SomethingWrong", false)]
        public async Task GivenGuiBuildPipeline_WhenCredScanTask_ThenEvaluatesToExpectedResult(string taskId, bool expectedResult)
        {
            //Assert
            _fixture.Customize<BuildProcess>(ctx => ctx
                .With(p => p.Type, 1));
            _fixture.Customize<BuildStep>(ctx => ctx
                .With(s => s.Enabled, true));
            _fixture.Customize<BuildTask>(ctx => ctx
                .With(t => t.Id, taskId));

            var buildPipeline = _fixture.Create<BuildDefinition>();
            var project = _fixture.Create<Project>();
            var client = Substitute.For<IVstsRestClient>();

            //Act
            var rule = new BuildPipelineHasCredScanTask(client);
            var result = await rule.EvaluateAsync(project, buildPipeline);

            //Assert
            result.ShouldBe(expectedResult);
        }

        [Theory]
        [InlineData("CredScan", true)]
        [InlineData("CredScanOdd", false)]
        public async Task GivenYamlBuildPipeline_WhenCredScanTask_ThenEvaluatesToExpectedResult(string taskName, bool expectedResult)
        {
            _fixture.Customize<BuildProcess>(ctx => ctx
                .With(p => p.Type, 2));
            _fixture.Customize<Project>(ctx => ctx
                .With(x => x.Name, "projectA"));
            _fixture.Customize<Repository>(ctx => ctx
                .With(r => r.Url, new Uri("https://projectA.nl")));

            var gitItem = new JObject
            {
                {"content", $"steps:\r- task: {taskName}"}
            };

            var buildPipeline = _fixture.Create<BuildDefinition>();
            var project = _fixture.Create<Project>();

            var client = Substitute.For<IVstsRestClient>();
            client.GetAsync(Arg.Any<IVstsRequest<JObject>>()).Returns(gitItem);

            var rule = new BuildPipelineHasCredScanTask(client);
            var result = await rule.EvaluateAsync(project, buildPipeline);

            result.ShouldBe(expectedResult);
        }
    }
}