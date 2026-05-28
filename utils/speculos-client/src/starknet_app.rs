use std::{borrow::Cow, time::Duration};

use crate::{AutomationAction, AutomationCondition, AutomationRule, Button, SpeculosClient};

/// Sets automation rules and, when [`ENABLE_BLIND_SIGN`] is among them, presses RIGHT so the
/// blind-sign flow advances immediately from the home screen to "App settings".
pub async fn set_automation(client: &SpeculosClient, rules: &[AutomationRule<'static>]) {
    client.automation(rules).await.unwrap();
    if rules.iter().any(|r| r == &ENABLE_BLIND_SIGN) {
        client
            .wait_for_events(Duration::from_secs(5))
            .await
            .unwrap();
        client.click_button(Button::Right).await.unwrap();
    }
}

// Screen flow: "Public Key (1/2)" -> Right -> "Public Key (2/2)" -> Right -> "Approve" -> Both
// Trigger fires on "Public Key (1/2)" and navigates to "Approve", then confirms.
pub const APPROVE_PUBLIC_KEY: AutomationRule<'static> = AutomationRule {
    text: Some(Cow::Borrowed("Public Key (1/2)")),
    regexp: None,
    x: None,
    y: None,
    conditions: &[],
    actions: &[
        // Right (to "Public Key (2/2)")
        AutomationAction::Button {
            button: Button::Right,
            pressed: true,
        },
        AutomationAction::Button {
            button: Button::Right,
            pressed: false,
        },
        // Right (to "Approve")
        AutomationAction::Button {
            button: Button::Right,
            pressed: true,
        },
        AutomationAction::Button {
            button: Button::Right,
            pressed: false,
        },
        // Both (confirm)
        AutomationAction::Button {
            button: Button::Left,
            pressed: true,
        },
        AutomationAction::Button {
            button: Button::Right,
            pressed: true,
        },
        AutomationAction::Button {
            button: Button::Left,
            pressed: false,
        },
        AutomationAction::Button {
            button: Button::Right,
            pressed: false,
        },
    ],
};

// Trigger fires on "App settings" screen: Both (enter) -> Both (toggle ON) -> sets blind_enabled=true.
// Use via set_automation(), which presses RIGHT after registering to navigate from home to "App settings".
pub const ENABLE_BLIND_SIGN: AutomationRule<'static> = AutomationRule {
    text: Some(Cow::Borrowed("App settings")),
    regexp: None,
    x: None,
    y: None,
    conditions: &[AutomationCondition {
        varname: Cow::Borrowed("blind_enabled"),
        value: false,
    }],
    actions: &[
        // Both (enter settings, shows "Blind signing" toggle OFF)
        AutomationAction::Button {
            button: Button::Left,
            pressed: true,
        },
        AutomationAction::Button {
            button: Button::Right,
            pressed: true,
        },
        AutomationAction::Button {
            button: Button::Left,
            pressed: false,
        },
        AutomationAction::Button {
            button: Button::Right,
            pressed: false,
        },
        // Both (toggle blind signing ON)
        AutomationAction::Button {
            button: Button::Left,
            pressed: true,
        },
        AutomationAction::Button {
            button: Button::Right,
            pressed: true,
        },
        AutomationAction::Button {
            button: Button::Left,
            pressed: false,
        },
        AutomationAction::Button {
            button: Button::Right,
            pressed: false,
        },
        // Mark as done
        AutomationAction::Setbool {
            varname: Cow::Borrowed("blind_enabled"),
            value: true,
        },
    ],
};

// Screen flow: "Blind signing ahead." -> Both -> "Review hash" -> Right -> "Hash (1/2)" ->
// Right -> "Hash (2/2)" -> Right -> "Sign Hash ?" -> Both -> "Message signed"
/// Must be used with [`ENABLE_BLIND_SIGN`].
pub const APPROVE_BLIND_SIGN_HASH: AutomationRule<'static> = AutomationRule {
    text: None,
    regexp: Some(Cow::Borrowed("^Blind signing ahead")),
    x: None,
    y: None,
    conditions: &[AutomationCondition {
        varname: Cow::Borrowed("blind_enabled"),
        value: true,
    }],
    actions: &[
        // Both (accept "Blind signing ahead" warning)
        AutomationAction::Button {
            button: Button::Left,
            pressed: true,
        },
        AutomationAction::Button {
            button: Button::Right,
            pressed: true,
        },
        AutomationAction::Button {
            button: Button::Left,
            pressed: false,
        },
        AutomationAction::Button {
            button: Button::Right,
            pressed: false,
        },
        // Right (to "Hash (1/2)")
        AutomationAction::Button {
            button: Button::Right,
            pressed: true,
        },
        AutomationAction::Button {
            button: Button::Right,
            pressed: false,
        },
        // Right (to "Hash (2/2)")
        AutomationAction::Button {
            button: Button::Right,
            pressed: true,
        },
        AutomationAction::Button {
            button: Button::Right,
            pressed: false,
        },
        // Right (to "Sign Hash ?")
        AutomationAction::Button {
            button: Button::Right,
            pressed: true,
        },
        AutomationAction::Button {
            button: Button::Right,
            pressed: false,
        },
        // Both (confirm)
        AutomationAction::Button {
            button: Button::Left,
            pressed: true,
        },
        AutomationAction::Button {
            button: Button::Right,
            pressed: true,
        },
        AutomationAction::Button {
            button: Button::Left,
            pressed: false,
        },
        AutomationAction::Button {
            button: Button::Right,
            pressed: false,
        },
    ],
};
