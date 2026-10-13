# Header assets

`header.png` is the README header, captured from `header.html` at 2x:

```sh
google-chrome --headless=new --disable-gpu --hide-scrollbars \
  --force-device-scale-factor=2 --window-size=1200,420 \
  --virtual-time-budget=10000 \
  --screenshot="$PWD/assets/header.png" \
  "file://$PWD/assets/header.html"
```
