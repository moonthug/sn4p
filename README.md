# sn4p

Snapchat v2 API for Node. Based on a PHP implementation by [mgp25](https://github.com/mgp25) http://github.com/mgp25/SC-API



### Version
0.0.1

### Installation

```sh
$ npm install https://github.com/moonthug/sn4p/tarball/master
```

### Examples
```javascript

var Sn4p = require('sn4p');

var options = {
    google: {
        // Your Google credentials
        email       : '',
        password    : ''
    },
    snapchat: {
        // Your snapchat credentials
        username    : '',
        password    : ''
    }
};

var sn4p = new Sn4p(options);
```

### Development

At present, it only retrieves Snaps and conversations.

It follows [mgp25](https://github.com/mgp25) implementation pretty closely opting for Node/JS syntax and conventions where appropriate.

Adding/porting over additional functionality should be fairly straight forward.

### Thanks

Thanks to [mgp25](https://github.com/mgp25) for great and everyone involved in the original PHP project for their hard work

### License

MIT

### Legal

This code is in no way affiliated with, authorized, maintained, sponsored or endorsed by Snapchat or any of its affiliates or subsidiaries. This is an independent and unofficial API. Use at your own risk.