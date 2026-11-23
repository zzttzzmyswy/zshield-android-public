package top.zztweb.zshield.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/*
 * ZShield design language.
 *
 * One brand hue (deep teal, the "shield") drives the Material 3 tonal scheme; light and dark are
 * separate, hand-checked schemes rather than an automatic inversion. Dynamic (wallpaper) colour is
 * deliberately not used: protection state is communicated through colour, so it must look the same
 * on every device.
 *
 * Status colours (protected / attention / blocked) are reserved and always paired with an icon and
 * a label, never used as decoration.
 */

private val LightColors: ColorScheme = lightColorScheme(
    primary = Color(0xFF006A63),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFF9EF2E7),
    onPrimaryContainer = Color(0xFF00201D),
    secondary = Color(0xFF4A6360),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFCCE8E3),
    onSecondaryContainer = Color(0xFF051F1C),
    tertiary = Color(0xFF456179),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFCCE5FF),
    onTertiaryContainer = Color(0xFF001E31),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
    background = Color(0xFFF4FBF9),
    onBackground = Color(0xFF161D1C),
    surface = Color(0xFFF4FBF9),
    onSurface = Color(0xFF161D1C),
    surfaceVariant = Color(0xFFDAE5E2),
    onSurfaceVariant = Color(0xFF3F4947),
    outline = Color(0xFF6F7977),
    outlineVariant = Color(0xFFBEC9C6),
    inverseSurface = Color(0xFF2B3231),
    inverseOnSurface = Color(0xFFECF2F0),
    inversePrimary = Color(0xFF82D5CB),
    surfaceTint = Color(0xFF006A63),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFEEF5F3),
    surfaceContainer = Color(0xFFE9EFED),
    surfaceContainerHigh = Color(0xFFE3EAE8),
    surfaceContainerHighest = Color(0xFFDDE4E2),
    surfaceBright = Color(0xFFF4FBF9),
    surfaceDim = Color(0xFFD5DBD9),
)

private val DarkColors: ColorScheme = darkColorScheme(
    primary = Color(0xFF82D5CB),
    onPrimary = Color(0xFF003733),
    primaryContainer = Color(0xFF00504B),
    onPrimaryContainer = Color(0xFF9EF2E7),
    secondary = Color(0xFFB0CCC7),
    onSecondary = Color(0xFF1C3532),
    secondaryContainer = Color(0xFF334B48),
    onSecondaryContainer = Color(0xFFCCE8E3),
    tertiary = Color(0xFFADCAE6),
    onTertiary = Color(0xFF153349),
    tertiaryContainer = Color(0xFF2D4960),
    onTertiaryContainer = Color(0xFFCCE5FF),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF0E1514),
    onBackground = Color(0xFFDDE4E2),
    surface = Color(0xFF0E1514),
    onSurface = Color(0xFFDDE4E2),
    surfaceVariant = Color(0xFF3F4947),
    onSurfaceVariant = Color(0xFFBEC9C6),
    outline = Color(0xFF899390),
    outlineVariant = Color(0xFF3F4947),
    inverseSurface = Color(0xFFDDE4E2),
    inverseOnSurface = Color(0xFF2B3231),
    inversePrimary = Color(0xFF006A63),
    surfaceTint = Color(0xFF82D5CB),
    surfaceContainerLowest = Color(0xFF090F0F),
    surfaceContainerLow = Color(0xFF161D1C),
    surfaceContainer = Color(0xFF1A2120),
    surfaceContainerHigh = Color(0xFF252B2A),
    surfaceContainerHighest = Color(0xFF2F3635),
    surfaceBright = Color(0xFF343B3A),
    surfaceDim = Color(0xFF0E1514),
)

/** Reserved status colours; every use pairs them with an icon and a text label. */
@Immutable
data class StatusColors(
    /** Protection on / healthy. */
    val good: Color,
    val onGood: Color,
    val goodContainer: Color,
    val onGoodContainer: Color,
    /** Needs the user's attention (e.g. strict Private DNS), not an error. */
    val warning: Color,
    val warningContainer: Color,
    val onWarningContainer: Color,
)

private val LightStatus = StatusColors(
    good = Color(0xFF006A63),
    onGood = Color(0xFFFFFFFF),
    goodContainer = Color(0xFF9EF2E7),
    onGoodContainer = Color(0xFF00201D),
    warning = Color(0xFF7A5900),
    warningContainer = Color(0xFFFFDEA6),
    onWarningContainer = Color(0xFF261900),
)

private val DarkStatus = StatusColors(
    good = Color(0xFF82D5CB),
    onGood = Color(0xFF003733),
    goodContainer = Color(0xFF00504B),
    onGoodContainer = Color(0xFF9EF2E7),
    warning = Color(0xFFF5BF48),
    warningContainer = Color(0xFF5C4200),
    onWarningContainer = Color(0xFFFFDEA6),
)

val LocalStatusColors = staticCompositionLocalOf { LightStatus }

/** Monospace style for rule text and URLs, where exact characters matter. */
val MonoStyle = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp, lineHeight = 16.sp)

private val AppTypography: Typography = Typography().let { base ->
    base.copy(
        // Hero numbers: tabular figures so a ticking counter does not jitter horizontally.
        displaySmall = base.displaySmall.copy(fontWeight = FontWeight.SemiBold, fontFeatureSettings = "tnum"),
        headlineMedium = base.headlineMedium.copy(fontWeight = FontWeight.SemiBold, fontFeatureSettings = "tnum"),
        headlineSmall = base.headlineSmall.copy(fontWeight = FontWeight.SemiBold),
        titleLarge = base.titleLarge.copy(fontWeight = FontWeight.SemiBold),
        titleMedium = base.titleMedium.copy(fontWeight = FontWeight.Medium),
        labelLarge = base.labelLarge.copy(fontWeight = FontWeight.Medium),
    )
}

@Composable
fun ZShieldTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    val status = if (darkTheme) DarkStatus else LightStatus
    androidx.compose.runtime.CompositionLocalProvider(LocalStatusColors provides status) {
        MaterialTheme(
            colorScheme = if (darkTheme) DarkColors else LightColors,
            typography = AppTypography,
            content = content,
        )
    }
}
