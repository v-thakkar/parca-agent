docker_prune_settings(num_builds=5)

## Parca Agent

docker_build(
    'parca.io/parca/parca-agent:dev', '',
     dockerfile='Dockerfile.dev',
)
k8s_yaml('deploy/tilt/parca-agent-daemonSet.yaml')
k8s_resource('parca-agent', port_forwards=[7071])
