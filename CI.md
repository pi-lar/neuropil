### Setup
To setup this CI pipeline we recomend to use the gitlab.com built in pipeline.

Please follow those steps:
 - fork the neuropil repository on gitlab.com
 - enable the Shared Runners(1)
 - create a gitlab deploy token(2) named "gitlab-deploy-token" with the following permissions:
   - read_repository
   - read_registry
   - write_registry
   - read_package_registry
   - write_package_registry

After this every push to the remote git repository should result in a pipeline run.

1 = https://docs.gitlab.com/ee/ci/runners/#shared-runners  
2 = https://docs.gitlab.com/ee/user/project/deploy_tokens/index.html#gitlab-deploy-token