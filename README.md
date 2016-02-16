# ansible-lxc-ssh
Ansible connection plugin using ssh + lxc-attach

## Description

This plugin allows to use Ansible on a remote server hosting LXC containers,
without having to install SSH servers in each LXC container.

The plugin connects to the host using SSH, then uses `lxc-attach` to enter the
container. This means the SSH connection must login as `root`, otherwise
`lxc-attach` will fail.

## Configuration

Add to `ansible.cfg`:
```
[defaults]
connection_plugins = /path/to/connection_plugins/lxc_ssh
```

Then, modify your `hosts` file to use the `lxc_ssh` transport:
```
container ansible_host=server ansible_connection=lxc_ssh ansible_ssh_extra_args=container
```

## notes

*     I haven't found any proper method to access the 'inventory_name' from the connection plugin, so I used 'ansible_ssh_extra_args' to store the name of the container.

