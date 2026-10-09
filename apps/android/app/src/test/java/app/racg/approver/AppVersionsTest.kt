package app.racg.approver

import org.junit.Assert.assertEquals
import org.junit.Test

class AppVersionsTest {
    @Test
    fun `matches Go version compare semantics`() {
        assertEquals(-1, AppVersions.compare("0.6.0", "0.6.2"))
        assertEquals(0, AppVersions.compare("0.6.2", "0.6.2"))
        assertEquals(1, AppVersions.compare("0.6.10", "0.6.2"))
        assertEquals(1, AppVersions.compare("0.10.0", "0.9.9"))
        assertEquals(-1, AppVersions.compare("0.6", "0.6.1"))
        assertEquals(0, AppVersions.compare("v0.6.2", "0.6.2"))
        assertEquals(0, AppVersions.compare("0.6.2+build", "0.6.2"))
    }

    @Test
    fun `prerelease ordering matches Go`() {
        assertEquals(-1, AppVersions.compare("0.6.3-0-gabc1234", "0.6.3"))
        assertEquals(-1, AppVersions.compare("0.6.3-alpha", "0.6.3-beta"))
        // Semver rule 11 (and Go port): numeric identifiers sort before
        // alphanumeric ones.
        assertEquals(-1, AppVersions.compare("0.6.3-1", "0.6.3-alpha"))
        assertEquals(-1, AppVersions.compare("0.6.3-1", "0.6.3-1.1"))
        assertEquals(1, AppVersions.compare("0.4.2", "0.4.2-rc.1"))
        assertEquals(1, AppVersions.compare("0.4.2-rc.2", "0.4.2-rc.1"))
    }

    @Test
    fun `garbage numeric parts treat as zero like Go`() {
        assertEquals(0, AppVersions.compare("x.y", "0.0"))
        assertEquals(1, AppVersions.compare("0.6.2", "x.y.z"))
    }
}
