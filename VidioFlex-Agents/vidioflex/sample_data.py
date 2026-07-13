"""Bundled demo transcript for offline simulation runs.

A ~12-minute two-speaker podcast episode ("Signal & Noise" interviewing a
behavioral scientist about habit formation). The conversation has three
distinct retention peaks — an emotional story arc, a dense framework
explanation, and a sharp topical pivot — surrounded by ordinary interview
chatter, so the HookExtractor has a realistic signal-to-noise landscape to
work against.
"""

from __future__ import annotations

from .state import SourceVideo, TranscriptSegment

# (duration_seconds, speaker, text) — timestamps are accumulated in order.
_RAW_SEGMENTS: list[tuple[float, str, str]] = [
    # --- Cold open & introductions -------------------------------------------------
    (11.0, "Maya", "Welcome back to Signal and Noise, the show about the machinery underneath everyday behavior."),
    (12.0, "Maya", "My guest is Dr. Elias Ward, a behavioral scientist who has spent eleven years studying why routines stick and why they quietly fall apart."),
    (9.0, "Elias", "Thanks for having me, Maya. Happy to dig into the messy parts."),
    (11.0, "Maya", "So, before the research, I want to start with something you mentioned backstage about your third year."),
    (12.0, "Elias", "You know, people assume behavioral data is tidy. It is not. Most of what we learned came from watching plans fall apart in slow motion."),
    (11.0, "Maya", "Well, then take me to that third spring, when the study was supposed to wrap."),
    (12.0, "Elias", "On paper everything looked fine. The retention curves were smooth, the committee liked our graphs, and I was already drafting the victory lap."),
    (10.0, "Maya", "And then the follow-up numbers came in."),
    # --- Retention peak 1: the emotional story arc ---------------------------------
    (12.0, "Elias", "Here's the part nobody warns you about. Half our participants relapsed within ten days of the study ending."),
    (12.0, "Elias", "Not a gentle fade, a cliff. People who had meditated ninety straight days just quit, and the shame curdled into panic when we called."),
    (12.0, "Elias", "One participant told me the broken streak wrecked her confidence so badly she hid the meditation app inside a folder named taxes."),
    (11.0, "Maya", "That detail is brutal. A folder named taxes."),
    (13.0, "Elias", "90 days of momentum, wrecked in one miserable weekend. I sat in the parking lot, stunned, convinced the whole program was ruined."),
    (12.0, "Elias", "We had built a machine that manufactured streaks, and the streaks were secretly manufacturing dread."),
    (12.0, "Elias", "The nightmare was never the missed day. The nightmare was how much our best people dreaded starting over."),
    (12.0, "Elias", "So we shelved the victory lap and spent the next two years studying the collapse instead of the streaks."),
    # --- Interview middle: diaries and dead ends -----------------------------------
    (11.0, "Maya", "So, when you say you studied the collapse, what did that actually look like day to day?"),
    (12.0, "Elias", "Mostly interviews and diaries. We asked people to write down what happened in the hour before they skipped."),
    (11.0, "Elias", "And the answers were boring in the most useful way. Nobody skipped because of a character flaw."),
    (12.0, "Maya", "And what were the patterns in the diaries, once you coded them all?"),
    (12.0, "Elias", "Context shifts. Travel, guests visiting, a new work schedule. The environment changed and the routine had no anchor anymore."),
    (11.0, "Maya", "And that reframing is what eventually led you to the model in the book."),
    (12.0, "Elias", "It took a while longer, honestly. We chased a few dead ends around reminders and rewards first."),
    (11.0, "Elias", "Reminder apps worked for about nine days on average, and then people started swiping them away without reading."),
    (12.0, "Maya", "And I think everyone listening has done that exact swipe at some point this week."),
    (11.0, "Elias", "Right, and that swipe is the interesting part. The brain learned the notification meant obligation, not payoff."),
    (12.0, "Maya", "And so payments and rewards were the next dead end you chased down."),
    (11.0, "Elias", "We paid one group for streaks and the payments worked until they stopped, and then that group did worse than the control."),
    # --- Retention peak 2: the dense framework -------------------------------------
    (11.0, "Elias", "Three ingredients decide whether a habit survives. Powerful routines are engineered from a stable anchor, a shrunken ritual, and an identity receipt."),
    (11.0, "Elias", "The anchor is an existing behavior, brushing teeth, morning coffee, closing the laptop, something the day already guarantees."),
    (11.0, "Elias", "The ritual must shrink until starting feels almost embarrassing, two pushups, one sentence in the journal, thirty seconds of stretching."),
    (12.0, "Elias", "The identity receipt is the sentence you say afterward: I am the kind of person who shows up. That sentence is the actual product."),
    (11.0, "Elias", "Anchor, ritual, receipt. Repeat that compression loop and the habit stops being a decision and becomes furniture in your day."),
    (11.0, "Maya", "And that furniture line is going on a poster somewhere, I promise."),
    # --- Interview middle: evidence and edge cases ---------------------------------
    (12.0, "Elias", "We tested the compression loop with four hundred people across three cohorts and the completion curves finally bent the right way."),
    (11.0, "Maya", "So what did the numbers actually show once you hit the six month mark?"),
    (12.0, "Elias", "Sixty-two percent were still practicing daily at six months, against nineteen percent in the classic goal-setting control group."),
    (11.0, "Maya", "And the effect held even for people who had struggled with routines for years."),
    (12.0, "Maya", "Let's take a quick beat here, because I want to ask about the people this loop does not work for."),
    (11.0, "Elias", "Shift workers are the honest answer. When the day has no stable spine, anchors keep dissolving."),
    (12.0, "Elias", "For them we prescribe event anchors instead of time anchors, the first coffee at work, the badge scan, the locker door."),
    (11.0, "Maya", "And that flexibility feels more humane than the streak apps we started this conversation with."),
    (12.0, "Elias", "Streaks are a fine scoreboard and a lousy boss. We tell people to count total repetitions, not consecutive days."),
    (11.0, "Maya", "Okay, I want to move to the part of the book that genuinely surprised me."),
    (11.0, "Maya", "Chapter nine. You spend forty pages dismantling motivation, and I read it twice to make sure you meant it."),
    # --- Retention peak 3: the motivation pivot ------------------------------------
    (12.0, "Elias", "Forget motivation. The dopamine research wrecked my assumptions, and honestly the whole popular story is backwards."),
    (12.0, "Elias", "Dopamine doesn't reward the win, it fires on the gap between prediction and reality. Your brain is obsessed with surprise, not success."),
    (11.0, "Elias", "That is why week three feels so hollow. The predictions catch up, the surprise dies, and the reward signal flatlines."),
    (12.0, "Elias", "So you stop chasing the feeling and start banking the receipts. Identity evidence compounds even on days when dopamine ghosts you."),
    (11.0, "Elias", "Motivation is weather. Identity is climate. Build for climate and the daily forecast stops mattering."),
    (11.0, "Maya", "Weather versus climate. That might be the cleanest framing of it I have heard on this show."),
    # --- Listener questions & outro -------------------------------------------------
    (12.0, "Maya", "Let's do a few listener questions before we wrap, because the inbox was completely full this week."),
    (11.0, "Maya", "Dana from Portland asks how long she should wait before adding a second habit to the stack."),
    (12.0, "Elias", "Wait until the first one survives a bad week without negotiation, which is usually about six weeks, then stack the next behind it."),
    (11.0, "Maya", "And Marcus in Austin wants to know whether the loop works for quitting things, not just starting them."),
    (12.0, "Elias", "It does, but you invert it. You redesign the anchor so the old cue points at a replacement ritual instead of at nothing."),
    (11.0, "Maya", "Nothing is not a strategy, as chapter eleven says."),
    (11.0, "Elias", "Exactly. A vacuum always loses to a plan, even a small plan."),
    (12.0, "Maya", "Before we close, tell people where the new cohort study is recruiting, because I know you need night-shift nurses."),
    (11.0, "Elias", "The signup is in the show notes, and yes, if you work nights in healthcare we would genuinely love your data."),
    (12.0, "Maya", "And the book, The Compression Loop, is out on the fourteenth everywhere books are sold."),
    (11.0, "Elias", "With an audiobook read by me, so apologies in advance for the accent drifting around."),
    (11.0, "Maya", "It's a good accent. Elias Ward, thank you for the most useful hour this show has had in a while."),
    (11.0, "Elias", "Thank you, Maya. Same time next relapse."),
    (12.0, "Maya", "That's the show. Signal and Noise is produced by the Overcast Collective, and we will see you in two weeks."),
]


def load_sample_transcript() -> tuple[SourceVideo, list[TranscriptSegment]]:
    """Materialize the demo episode as typed state models."""
    segments: list[TranscriptSegment] = []
    cursor = 0.0
    for segment_id, (duration, speaker, text) in enumerate(_RAW_SEGMENTS):
        segments.append(
            TranscriptSegment(
                segment_id=segment_id,
                start=round(cursor, 3),
                end=round(cursor + duration, 3),
                speaker=speaker,
                text=text,
            )
        )
        cursor += duration

    source = SourceVideo(
        video_id="sn-ep-147",
        title="The Hidden Engineering of Habits — Signal & Noise Ep. 147",
        duration_seconds=round(cursor + 4.0, 3),
        language="en",
        creator_handle="@signalnoiseshow",
    )
    return source, segments
