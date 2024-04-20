### Setup
To setup this CI pipeline we recomend to use the gitlab.com built in pipeline.

Please follow those steps:
 - fork the neuropil repository on gitlab.com
 - enable the Shared Runners(1)

If you want to build on different runners (f.e. for different toolchains) please use the `DYNAMIC_BUILDERS` environment variable.
Every line of this variable may indicate a seperate runner and provide runners with this tag prefixed by `neuropil-`  
So to provide a runner for "abc-system" provide a runner with the tag "neuropil-abc-system" and add a new line "abc-system" to the `DYNAMIC_BUILDERS` environment variable.

After this every push to the remote git repository should result in a pipeline run.

1 = https://docs.gitlab.com/ee/ci/runners/#shared-runners  
2 = https://docs.gitlab.com/ee/user/project/deploy_tokens/index.html#gitlab-deploy-token