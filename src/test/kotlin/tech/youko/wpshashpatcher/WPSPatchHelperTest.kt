package tech.youko.wpshashpatcher

import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class WPSPatchHelperTest {
    @Test
    fun `supports bit masks and full byte wildcards`() {
        val data = ByteBuffer.wrap(byteArrayOf(0xA5.toByte(), 0xB5.toByte(), 0xA6.toByte()))

        assertEquals(listOf(0, 1), findPattern(data, intArrayOf(0x05), intArrayOf(0xF0)))
        assertEquals(listOf(0, 1, 2), findPattern(data, intArrayOf(0), intArrayOf(0xFF)))
    }

    @Test
    fun `patches x86 KRSAVerifyFile and remains idempotent`() {
        verifyPatch(
            Architecture.I386,
            "55 8B EC",
            "C7 06 11 22 33 44 C7 46 04 55 66 77 88 EB 02 33 F6 83 7F 14 10 C6 45 FC 00",
            "B0 01 C3"
        )
    }

    @Test
    fun `patches x64 KRSAVerifyFile and remains idempotent`() {
        verifyPatch(
            Architecture.AMD64,
            "40 53 56",
            "4C 8D 3D 11 22 33 44 4C 89 3F 4C 8D 25 55 66 77 88 4C 89 67 08",
            "B0 01 C3"
        )
    }

    @Test
    fun `patches ARM64 KRSAVerifyFile and remains idempotent`() {
        verifyPatch(
            Architecture.ARM64,
            "FD 7B BF A9",
            "49 A3 02 A9 68 1C 00 D0 08 A1 1F 91 40 03 01 91 48 53 00 F9",
            "20 00 80 52 C0 03 5F D6"
        )
    }

    @Test
    fun `falls back to ARM64 pattern for an AMD64-marked ARM64X image`() {
        verifyPatch(
            Architecture.AMD64,
            "FD 7B BF A9",
            "49 A3 02 A9 68 1C 00 D0 08 E1 04 91 40 03 01 91 48 53 00 F9",
            "20 00 80 52 C0 03 5F D6"
        )
    }

    private fun verifyPatch(architecture: Architecture, prologue: String, anchor: String, replacement: String) {
        val input = ByteArray(256) { 0x7E }
        hex(prologue).copyInto(input, 32)
        hex(anchor).copyInto(input, 128)
        val data = ByteBuffer.wrap(input)

        patchExecutableFile(data, architecture)
        assertContentEquals(hex(replacement), input.copyOfRange(32, 32 + hex(replacement).size))

        patchExecutableFile(data, architecture)
        assertContentEquals(hex(replacement), input.copyOfRange(32, 32 + hex(replacement).size))
    }

    private fun hex(value: String): ByteArray = value.split(' ').map { it.toInt(16).toByte() }.toByteArray()
}
