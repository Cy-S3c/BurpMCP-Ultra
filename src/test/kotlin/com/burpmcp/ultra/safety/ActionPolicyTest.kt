package com.burpmcp.ultra.safety

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ActionPolicyTest {

    @Test
    fun `classifies the destructive tools`() {
        assertTrue(ActionPolicy.isDestructive("burp_shutdown"))
        assertTrue(ActionPolicy.isDestructive("burp_import_project_config"))
        assertTrue(ActionPolicy.isDestructive("burp_import_user_config"))
        assertFalse(ActionPolicy.isDestructive("http_send_request"))
    }

    @Test
    fun `non-destructive tools are always allowed`() {
        assertTrue(ActionPolicy.isAllowed("http_send_request", allowDestructive = false))
        assertTrue(ActionPolicy.isAllowed("proxy_history", allowDestructive = false))
    }

    @Test
    fun `destructive tools are allowed only when the operator opts in`() {
        assertFalse(ActionPolicy.isAllowed("burp_shutdown", allowDestructive = false))
        assertTrue(ActionPolicy.isAllowed("burp_shutdown", allowDestructive = true))
        assertFalse(ActionPolicy.isAllowed("burp_import_user_config", allowDestructive = false))
    }
}
