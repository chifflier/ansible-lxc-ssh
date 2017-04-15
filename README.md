# ansible-lxc-ssh
Ansible connection plugin using ssh + lxc-attach

## Description

This plugin allows to use Ansible on a remote server hosting LXC containers,
without having to install SSH servers in each LXC container.

The plugin connects to the host using SSH, then uses `lxc` or `lxc-attach` to enter the
container.

For LXC version 1 this means the SSH connection must login as `root`, otherwise
`lxc-attach` will fail.

For LXC version 2 this means that the user must either login as `root` or must be
in the `lxc` group in order to execute the `lxc` command.


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


## Form

This is a fork from the original plugin:

[ansible-lxc-ssh by Pierre Chifflier](https://github.com/chifflier/ansible-lxc-ssh)

This fork incorporates a few PRs from the original version, which (April 2017) were never
applied. It also works with LXC version 1 (using `lxc-*`) and LXC version 2 (just using
a single `lxc` binary). The version is autodetected on runtime.


## notes

*     I haven't found any proper method to access the 'inventory_name' from the connection plugin, so I used 'ansible_ssh_extra_args' to store the name of the container.

