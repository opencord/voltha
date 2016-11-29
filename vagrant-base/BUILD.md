# How to Build Voltha-Base

There are many ways to build and develop Voltha

* Use the provided Vagrant environment. This mode is by far the most reliable, and the only one officially supported.
* Use your native MAC OS or Linux environments. These are not supported, although we provide guidance in a best effort manner and contributions/patches are graciously accepted from the community.

## What triggers the need for a new voltha-base

```
WHAT WE NEED TO CONSIDER AS A REASON TO CREATE A NEW IMAGE
```

## The process of building and testing the new voltha base image

### Prerequisites

* Git client
* Working installation of Vagrant  -- see [https://www.vagrantup.com/downloads.html](https://www.vagrantup.com/downloads.html)
* jq -- a useful command line too to work with JSON data. On the MAC, you can install jq with ```brew install jq```; on Ubuntu you can do it with ```sudo apt-get install jq```. You will not regret it.


### Build

If you have not cloned Voltha, it's time to do it now. If you just want to check it out, you can do it anonymously:

```
git clone https://gerrit.opencord.org/voltha
```

If you want to develop it, you better use your Gerrit credentials and clone is as (substitute your user name):

```
git clone ssh://<your-gerrit-user-name>@gerrit.opencord.org:29418/voltha
```

You can build Voltha by:

```
cd vagrant-base
vagrant up  # when you do this for the first time, this will take considerable time
vagrant ssh # to see if image is there and accessible
```

The above has generated a new Vagrant image, named ```voltha-base``` . To check status of the image, first exit from the image and then run status command:

```
# when (and if) inside the vagrant image, exit first
exit
# and then check the image status
vagrant status
```
This should produce an output like this:
```
Current machine states:

voltha-base               running (virtualbox)

The VM is running. To stop this VM, you can run `vagrant halt` to
shut it down forcefully, or you can run `vagrant suspend` to simply
suspend the virtual machine. In either case, to restart it again,
simply run `vagrant up`.
```

### Test

Once image is created and machine is running, as mentioned in previous steps, we can run the following script and test the sanity of the image before uploading it into Vagrant cloud.

```./test_script.sh```

In case the script can't get executed, change the access permission of the script using ```sudo chmod 755 ./test_script.sh```.

## Creating a new vagrant box - The process of bumping the version number of voltha-base

Once vagrant image is created, we can use this base image and package it and create a vagrant box of it.

```
vagrant package
```

This should create a file named ```package.box```

### Creating a new version on the vagrant cloud

At this point we need to create a new version and POST it in the Vagrant Cloud. To do so, we need to create a version.

```
curl https://atlas.hashicorp.com/api/v1/box/rrashidi/voltha-base/versions -X POST -H "X-Atlas-Token: <DEDICATED_VOLTHA_BASE_TOKEN>" -d version[version]='<YOUR_DESIRED_VERSION>' -d version[description]='This is your description' | jq
```

The result should look something like this:

```
{
  "version": "<YOUR_DESIRED_VERSION>",
  "status": "unreleased",
  "description_html": "<p>This is your description</p>\n",
  "description_markdown": "This is your description",
  "created_at": "2016-11-29T15:35:21.103Z",
  "updated_at": "2016-11-29T15:35:21.103Z",
  "number": "<YOUR_DESIRED_VERSION>",
  "release_url": "https://atlas.hashicorp.com/api/v1/box/rrashidi/voltha-base/version/<YOUR_DESIRED_VERSION>/release",
  "revoke_url": "https://atlas.hashicorp.com/api/v1/box/rrashidi/voltha-base/version/<YOUR_DESIRED_VERSION>/revoke",
  "providers": []
}
```
### Creating a provider for the new version on the vagrant cloud

Now, we need to create a provider for the newly-created version. We use VirtualBox as the provider.

```
url https://atlas.hashicorp.com/api/v1/box/rrashidi/voltha-base/version/<YOUR_DESIRED_VERSION>/providers -X POST -H "X-Atlas-Token: <DEDICATED_VOLTHA_BASE_TOKEN>" -d provider[name]='virtualbox' | jq
```

The result should look something like this:

```
{
  "name": "virtualbox",
  "hosted": true,
  "hosted_token": null,
  "original_url": null,
  "created_at": "2016-11-29T16:00:17.604Z",
  "updated_at": "2016-11-29T16:00:17.604Z",
  "download_url": "https://atlas.hashicorp.com/rrashidi/boxes/voltha-base/versions/<YOUR_DESIRED_VERSION>/providers/virtualbox.box"
}
```

### Uploading the newly created vagrant package to vagrant cloud

We need to upload the package.box file for the provider.

```
curl 'https://atlas.hashicorp.com/api/v1/box/rrashidi/voltha-base/version/<YOUR_DESIRED_VERSION>/provider/virtualbox/upload?access_token=<DEDICATED_VOLTHA_BASE_TOKEN>' | jq
```

The result should look something like this:

```
{
  "upload_path": "https://binstore-test.hashicorp.com/a5bfcdf9-609b-4e8f-b5b8-d9ebdea4d2c6",
  "token": "a5bfcdf9-609b-4e8f-b5b8-d9ebdea4d2c6"
}
```

Then, we upload the .box file using the upload_path.

```
curl -X PUT --upload-file package.box https://binstore-test.hashicorp.com/a5bfcdf9-609b-4e8f-b5b8-d9ebdea4d2c6
```

Now that provider of the version and the vagrant image package is ready, we need to realese the version. To release a version to be accessible to all the users, we should use the provided release-url.

```
curl https://atlas.hashicorp.com/api/v1/box/rrashidi/voltha-base/version/<YOUR_DESIRED_VERSION>/release -X PUT -H "X-Atlas-Token: <DEDICATED_VOLTHA_BASE_TOKEN>" | jq
```

The result should look something like this:

```
{
  "version": "<YOUR_DESIRED_VERSION>",
  "status": "active",
  "description_html": "<p>This is your description</p>\n",
  "description_markdown": "This is your description",
  "created_at": "2016-11-29T15:48:50.809Z",
  "updated_at": "2016-11-29T16:15:14.471Z",
  "number": "0.1.3",
  "release_url": "https://atlas.hashicorp.com/api/v1/box/rrashidi/voltha-base/version/<YOUR_DESIRED_VERSION>/release",
  "revoke_url": "https://atlas.hashicorp.com/api/v1/box/rrashidi/voltha-base/version/<YOUR_DESIRED_VERSION>/revoke",
  "providers": [
    {
      "name": "virtualbox",
      "hosted": true,
      "hosted_token": "a5bfcdf9-609b-4e8f-b5b8-d9ebdea4d2c6",
      "original_url": null,
      "created_at": "2016-11-29T16:00:17.604Z",
      "updated_at": "2016-11-29T16:00:17.604Z",
      "download_url": "https://atlas.hashicorp.com/rrashidi/boxes/voltha-base/versions/<YOUR_DESIRED_VERSION>/providers/virtualbox.box"
    }
  ]
}
```

Following the execution of this command, the new version gets released. As the result, the previous version is not currently a released version. 

