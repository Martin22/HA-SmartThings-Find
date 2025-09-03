from typing import Any, Dict
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlowResult,
    OptionsFlowWithConfigEntry
)
from .const import (
    DOMAIN,
    CONF_ACCESS_TOKEN,
    CONF_CLIENT_ID,
    CONF_CODE_VERIFIER,
    CONF_UPDATE_INTERVAL,
    CONF_UPDATE_INTERVAL_DEFAULT,
    CONF_ACTIVE_MODE_SMARTTAGS,
    CONF_ACTIVE_MODE_SMARTTAGS_DEFAULT,
    CONF_ACTIVE_MODE_OTHERS,
    CONF_ACTIVE_MODE_OTHERS_DEFAULT
)
from .utils import do_login_stage_one
import asyncio
import logging
import hashlib
import base64
import secrets
import aiohttp

_LOGGER = logging.getLogger(__name__)

class SmartThingsFindConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    OAUTH2_AUTH_URL = "https://account.samsung.com/accounts/v1/FMM2/signInGate"
    OAUTH2_TOKEN_URL = "https://account.samsung.com/accounts/v1/FMM2/token"
    REDIRECT_URI = "https://smartthingsfind.samsung.com/login.do"
    CLIENT_ID = "ntly6zvfpn"  # Default client_id for SmartThings Find

    async def async_step_user(self, user_input=None):
        """Start OAuth2 PKCE flow: generate code_verifier, code_challenge, show auth URL and QR code."""
        # Generate PKCE code_verifier and code_challenge
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b'=').decode('utf-8')

        # Store for later
        self.code_verifier = code_verifier
        self.code_challenge = code_challenge

        # Build authorization URL
        state = secrets.token_urlsafe(16)
        auth_url = (
            f"{self.OAUTH2_AUTH_URL}?response_type=code"
            f"&client_id={self.CLIENT_ID}"
            f"&redirect_uri={self.REDIRECT_URI}"
            f"&code_challenge={code_challenge}"
            f"&code_challenge_method=S256"
            f"&scope=iot.client"
            f"&state={state}"
        )

        import qrcode
        from io import BytesIO
        import base64 as py_base64

        # Generate QR code as base64 PNG
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(auth_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = py_base64.b64encode(buf.getvalue()).decode("utf-8")

        # Show form with QR code and link, button to continue
        if user_input is not None:
            return await self.async_step_code()

        return self.async_show_form(
            step_id="user",
            description="<b>Přihlášení SmartThings Find</b><br><br>1. Otevřete <a href='{auth_url}' target='_blank'>tento odkaz</a> nebo naskenujte QR kód.<br><br><img src='{qr_code}' alt='QR kód' /><br><br>2. Přihlaste se Samsung účtem a zkopírujte autorizační kód.<br><br>Pokračujte tlačítkem níže.",
            description_placeholders={
                "auth_url": auth_url,
                "qr_code": f"data:image/png;base64,{qr_b64}"
            },
            data_schema=vol.Schema({}),
        )

    async def async_step_code(self, user_input=None):
        """Receive authorization code, exchange for tokens."""
        errors = {}
        if user_input is not None:
            code = user_input.get("code")
            if not code:
                errors["base"] = "missing_code"
            else:
                # Exchange code for tokens
                async with aiohttp.ClientSession() as session:
                    data = {
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": self.REDIRECT_URI,
                        "client_id": self.CLIENT_ID,
                        "code_verifier": self.code_verifier,
                    }
                    async with session.post(self.OAUTH2_TOKEN_URL, data=data) as resp:
                        if resp.status != 200:
                            errors["base"] = "token_error"
                        else:
                            tokens = await resp.json()
                            access_token = tokens.get("access_token")
                            refresh_token = tokens.get("refresh_token")
                            if not access_token or not refresh_token:
                                errors["base"] = "token_error"
                            else:
                                # Save tokens
                                data = {
                                    CONF_ACCESS_TOKEN: access_token,
                                    CONF_CLIENT_ID: self.CLIENT_ID,
                                    CONF_CODE_VERIFIER: self.code_verifier,
                                    "refresh_token": refresh_token,
                                }
                                return self.async_create_entry(title="SmartThings Find", data=data)

        return self.async_show_form(
            step_id="code",
            errors=errors,
            data_schema=vol.Schema({vol.Required("code"): str}),
        )

    # Odstraněna duplicitní definice async_step_code
    """Handle a config flow for SmartThings Find."""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_POLL

    reauth_entry: ConfigEntry | None = None

    task_stage_one: asyncio.Task | None = None
    task_stage_two: asyncio.Task | None = None

    qr_url = None
    session = None

    access_token = None
    client_id = None
    code_verifier = None


    error = None

    async def do_stage_one(self):
        _LOGGER.debug("Running login stage 1")
        try:
            stage_one_res = await do_login_stage_one(self.hass)
            if not stage_one_res is None:
                self.session, self.qr_url = stage_one_res
            else:
                self.error = "Login stage 1 failed. Check logs for details."
                _LOGGER.warn("Login stage 1 failed")
            _LOGGER.debug("Login stage 1 done")
        except Exception as e:
            self.error = "Login stage 1 failed. Check logs for details."
            _LOGGER.error(f"Exception in stage 1: {e}", exc_info=True)

    # async def do_stage_two(self):
    #     _LOGGER.debug("Running login stage 2")
    #     try: 
    #         stage_two_res = await do_login_stage_two(self.session)
    #         if not stage_two_res is None:
    #             self.jsessionid = stage_two_res
    #             _LOGGER.info("Login successful")
    #         else:
    #             self.error = "Login stage 2 failed. Check logs for details."
    #             _LOGGER.warning("Login stage 2 failed")
    #         _LOGGER.debug("Login stage 2 done")
    #     except Exception as e:
    #         self.error = "Login stage 2 failed. Check logs for details."
    #         _LOGGER.error(f"Exception in stage 2: {e}", exc_info=True)


    
    # # Second step: Wait until QR scanned an log in
    # async def async_step_auth_stage_two(self, user_input=None):
    #     if not self.task_stage_two:
    #         self.task_stage_two = self.hass.async_create_task(self.do_stage_two())
    #     if not self.task_stage_two.done():
    #         return self.async_show_progress(
    #             progress_action="task_stage_two",
    #             progress_task=self.task_stage_two,
    #             description_placeholders={
    #                 "qr_code": gen_qr_code_base64(self.qr_url),
    #                 "url": self.qr_url,
    #                 "code": self.qr_url.split('/')[-1],
    #             }
    #         )
    #     return self.async_show_progress_done(next_step_id="finish")

    # async_step_user je již definována výše (QR kód + odkaz + pole pro kód)

    # async_step_finish odstraněna, flow je řešen v async_step_user/code

    # async def async_step_finish(self, user_input=None):
    #     if self.error:
    #         return self.async_show_form(step_id="finish", errors={'base': self.error})
    #     data={CONF_JSESSIONID: self.jsessionid}
        
    #     if self.reauth_entry:
    #         # Finish step was called by reauth-flow. Do not create a new entry,
    #         # instead update the existing entry
    #         return self.async_update_reload_and_abort(
    #             self.reauth_entry,
    #             data=data
    #         )
        
        # return self.async_create_entry(title="SmartThings Find", data=data)

    async def async_step_reauth(self, user_input=None):
        self.reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        if user_input is None:
            return self.async_show_form(
                step_id="user",
                data_schema=vol.Schema({}),
            )
        return await self.async_step_user()
    
    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None):
        return await self.async_step_reauth_confirm(self)
    
    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Create the options flow."""
        return SmartThingsFindOptionsFlowHandler(config_entry)
    
    
class SmartThingsFindOptionsFlowHandler(OptionsFlowWithConfigEntry):
    """Handle an options flow."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle options flow."""

        if user_input is not None:

            res = self.async_create_entry(title="", data=user_input)

            # Reload the integration entry to make sure the newly set options take effect
            self.hass.config_entries.async_schedule_reload(self.config_entry.entry_id)
            return res

        data_schema = vol.Schema(
            {
                vol.Optional(
                    CONF_UPDATE_INTERVAL,
                    default=self.options.get(
                        CONF_UPDATE_INTERVAL, CONF_UPDATE_INTERVAL_DEFAULT
                    ),
                ): vol.All(vol.Coerce(int), vol.Clamp(min=30)),
                vol.Optional(
                    CONF_ACTIVE_MODE_SMARTTAGS,
                    default=self.options.get(
                        CONF_ACTIVE_MODE_SMARTTAGS, CONF_ACTIVE_MODE_SMARTTAGS_DEFAULT
                    ),
                ): bool,
                vol.Optional(
                    CONF_ACTIVE_MODE_OTHERS,
                    default=self.options.get(
                        CONF_ACTIVE_MODE_OTHERS, CONF_ACTIVE_MODE_OTHERS_DEFAULT
                    ),
                ): bool,
            }
        )
        return self.async_show_form(step_id="init", data_schema=data_schema)