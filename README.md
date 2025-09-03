# ⚠️ Original Repository archived - forked repository with login alternative quick fix ⚠️
Unfortunately, I no longer have the time to maintain this repository. I underestimated how much work it would be. Additionally, my focus recently has shifted away from HA (and programming in general) towards other things. I sincerely hope someone else can take over and build a solid, reliable integration from what's already here.

# SmartThings Find Integration for Home Assistant

This integration adds support for devices from Samsung SmartThings Find. While intended mainly for Samsung SmartTags, it also works with other devices, such as phones, tablets, watches and earbuds.

Currently the integration creates three entities for each device:
* `device_tracker`: Shows the location of the tag/device.
* `sensor`: Represents the battery level of the tag/device (not supported for earbuds!)
* `button`: Allows you to ring the tag/device.

![screenshot](media/screenshot_1.png)

This integration does **not** allow you to perform actions based on button presses on the SmartTag! There are other ways to do that.


## ⚠️ Warning/Disclaimer ⚠️

- **API Limitations**: Created by reverse engineering the SmartThings Find API, this integration might stop working at any time if changes occur on the SmartThings side.
- **Limited Testing**: The integration hasn't been thoroughly tested. If you encounter issues, please report them by creating an issue.
- **Feature Constraints**: The integration can only support features available on the [SmartThings Find website](https://smartthingsfind.samsung.com/). For instance, stopping a SmartTag from ringing is not possible due to API limitations (while other devices do support this; not yet implemented)

## Notes on authentication
This integration now uses OAuth2 PKCE authentication as described in [uTag wiki](https://github.com/KieronQuinn/uTag/wiki/Authentication). You will need to obtain your `access_token`, `client_id` and `code_verifier` using the PKCE flow. Follow the instructions in the uTag wiki to generate these values. Enter them in the Home Assistant integration setup form.

## Notes on connection to the devices
Being able to let a SmartTag ring depends on a phone/tablet nearby which forwards your request via Bluetooth. If your phone is not near your tag, you can't make it ring. The location should still update if any Galaxy device is nearby. 

If ringing your tag does not work, first try to let it ring from the [SmartThings Find website](https://smartthingsfind.samsung.com/). If it does not work from there, it can not work from Home Assistant too! Note that letting it ring with the SmartThings Mobile App is not the same as the website. Just because it does work in the App, does not mean it works on the web. So always use the web version to do your tests.

## Notes on active/passive mode

Starting with version 0.2.0, it is possible to configure whether to use the integration in an active or passive mode. In passive mode the integration only fetches the location from the server which was last reported to STF. In active mode the integration sends an actual "request location update" request. This will make the STF server try to connect to e.g. your phone, get the current location and send it back to the STF server from where the integration can then read it. This has quite a big impact on the devices battery and in some cases might also wake up the screen of the phone or tablet.

By default active mode is enabled for SmartTags but disabled for any other devices. You can change this behaviour on the integrations page by clicking on `Configure`. Here you can also set the update interval, which is set to 120 seconds by default.


## Installation Instructions

### Using HACS

1. Add this repository as a custom repository in HACS. Either by manually adding `https://github.com/tomskra/HA-SmartThings-Find` with category `integration` or simply click the following button:

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=tomskra&repository=HA-SmartThings-Find&category=integration)

2. Search for "SmartThings Find" in HACS and install the integration
3. Restart Home Assistant
4. Proceed to [Setup instructions](#setup-instructions)

### Manual install

1. Download the `custom_components/smartthings_find` directory to your Home Assistant configuration directory
2. Restart Home Assistant
3. Proceed to [Setup instructions](#setup-instructions)

## Setup Instructions

[![Open your Home Assistant instance and start setting up a new integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=smartthings_find)

1. Go to the Integrations page  
2. Search for "SmartThings *Find*" (**do not confuse this with the built-in SmartThings integration!**)  
3. Visit https://smartthingsfind.samsung.com/ and log in with your Samsung account.  
4. Open Developer Tools in your browser.  
5. Follow the instructions in [uTag wiki](https://github.com/KieronQuinn/uTag/wiki/Authentication) to obtain your `access_token`, `client_id` and `code_verifier` using the OAuth2 PKCE flow.  
6. Enter these values into Home Assistant during integration setup.  
7. Wait a few seconds for the integration to be ready.

## Debugging

To enable debugging, you need to set the log level in `configuration.yaml`:

```yaml
logger:
  default: info
  logs:
    custom_components.smartthings_find: debug
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributions

Contributions are welcome! Feel free to open issues or submit pull requests to help improve this integration.

## Support

For support, please create an issue on the GitHub repository.

## Roadmap

- No roadmap, unfortunately, I don't have time for adding features

## Disclaimer

This is a third-party integration and is not affiliated with or endorsed by Samsung or SmartThings.
