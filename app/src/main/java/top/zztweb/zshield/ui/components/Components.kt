package top.zztweb.zshield.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/** Content never stretches wider than this on tablets / landscape; it centres instead. */
val MaxContentWidth: Dp = 640.dp

/** Horizontal page margin used by every screen. */
val PageMargin: Dp = 16.dp

/** A section title inside a scrolling page, in the primary ink. */
@Composable
fun SectionHeader(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = modifier.padding(start = PageMargin + 4.dp, end = PageMargin, top = 20.dp, bottom = 8.dp),
    )
}

/**
 * An inline notice. [container]/[content] come from the status or error roles; the icon and title
 * always accompany the colour, so the message is never colour-only. With [onClick] the whole notice
 * is the target and a trailing chevron says so — tighter than an action button for "go and look".
 */
@Composable
fun Banner(
    icon: ImageVector,
    title: String,
    body: String?,
    container: Color,
    content: Color,
    modifier: Modifier = Modifier,
    action: (@Composable () -> Unit)? = null,
    onClick: (() -> Unit)? = null,
) {
    val body: @Composable () -> Unit = {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.Top) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(20.dp).padding(top = 1.dp))
            Spacer(Modifier.size(12.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(title, style = MaterialTheme.typography.titleSmall)
                if (body != null) Text(body, style = MaterialTheme.typography.bodyMedium)
                if (action != null) {
                    Spacer(Modifier.height(4.dp))
                    action()
                }
            }
            if (onClick != null) {
                Spacer(Modifier.size(8.dp))
                Icon(
                    Icons.AutoMirrored.Filled.KeyboardArrowRight,
                    contentDescription = null,
                    modifier = Modifier.align(Alignment.CenterVertically),
                )
            }
        }
    }
    val shape = RoundedCornerShape(16.dp)
    if (onClick != null) {
        Surface(
            onClick = onClick,
            color = container,
            contentColor = content,
            shape = shape,
            modifier = modifier.fillMaxWidth(),
            content = body,
        )
    } else {
        Surface(
            color = container,
            contentColor = content,
            shape = shape,
            modifier = modifier.fillMaxWidth(),
            content = body,
        )
    }
}

/** Centered empty / unavailable state with an icon, a title and one line of guidance. */
@Composable
fun EmptyState(icon: ImageVector, title: String, body: String, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.padding(horizontal = 32.dp, vertical = 48.dp).widthIn(max = 360.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Surface(
            shape = RoundedCornerShape(28.dp),
            color = MaterialTheme.colorScheme.surfaceContainerHigh,
            contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(72.dp),
        ) {
            Icon(icon, contentDescription = null, modifier = Modifier.padding(20.dp))
        }
        Spacer(Modifier.height(16.dp))
        Text(title, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
        Spacer(Modifier.height(6.dp))
        Text(
            body,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

/** Grouped card container used for lists of settings / filter rows. */
@Composable
fun GroupCard(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Surface(
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        modifier = modifier.fillMaxWidth().padding(horizontal = PageMargin),
    ) {
        Column(Modifier.padding(vertical = 4.dp)) { content() }
    }
}

/** Bottom padding that keeps the last item clear of a FAB. */
val FabClearance = PaddingValues(bottom = 88.dp)
