# easyhook-h5gg
EasyHook-js 

# a simple way to hook offsets from game-frameworks within h5gg 
# H5GG PLUGIN H5FRIDA MUST BE INSTALLED BEFORE USAGE
- this is available on the official h5gg github

 # usage example
```
const main = easyhook.hook("GameBinary!main");
const second = main + 0x20; // offset here          
easyhook.intercept(second, {
  onEnter: function(args) { send("entered"); }
});
```
