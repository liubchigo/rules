﻿using System.Collections.Generic;
using AutoFixture;
using SecurePipelineScan.Rules.Security;
using SecurePipelineScan.VstsService.Response;
using Shouldly;
using Xunit;
using Task = System.Threading.Tasks.Task;

namespace SecurePipelineScan.Rules.Tests.Security
{
    public class ReleasePipelineUsesBuildArtifactTests : IClassFixture<TestConfig>
    {
        private readonly TestConfig _config;

        public ReleasePipelineUsesBuildArtifactTests(TestConfig config)
        {
            _config = config;
        }

        [Fact]
        public async Task ReturnFalseForReleasePipelineWithoutArtifacts()
        {
            //Arrange
            var fixture = new Fixture();
            var releasePipeline = fixture.Create<ReleaseDefinition>();
            releasePipeline.Artifacts = new List<Artifact>();

            //Act
            var rule = new ReleasePipelineUsesBuildArtifact();
            var result = await rule.EvaluateAsync(_config.Project, releasePipeline);

            //Assert
            result.ShouldBe(false);
        }
    }
}