<?php
/**
 * Resume Parser - Extracts structured data from resume text
 */

function parseResumeContent($raw_text) {
    $parsed = [
        'name' => '',
        'email' => '',
        'phone' => '',
        'location' => '',
        'job_title' => '',
        'about' => '',
        'skills' => [],
        'experience' => [],
        'projects' => [],
        'certifications' => [],
        'social_links' => []
    ];

    // Extract email
    if (preg_match('/([a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i', $raw_text, $match)) {
        $parsed['email'] = $match[1];
    }

    // Extract phone
    if (preg_match('/(?:\+\d{1,3}[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})/i', $raw_text, $match)) {
        $parsed['phone'] = $match[0];
    }

    // Extract name (usually first line or before contact info)
    $lines = array_filter(array_map('trim', explode("\n", $raw_text)));
    if (!empty($lines)) {
        $first_line = reset($lines);
        if (strlen($first_line) < 100 && !preg_match('/[0-9@#]/', $first_line)) {
            $parsed['name'] = $first_line;
        }
    }

    // Extract job title
    $title_patterns = [
        '/(?:title|position|role|current\s+role):\s*([^\n]+)/i',
        '/(?:Senior|Junior|Lead|Staff|Principal)\s+\w+/i',
        '/\w+\s+(?:Engineer|Developer|Designer|Manager|Analyst)/i'
    ];

    foreach ($title_patterns as $pattern) {
        if (preg_match($pattern, $raw_text, $match)) {
            $parsed['job_title'] = trim($match[1] ?? $match[0]);
            break;
        }
    }

    // Extract skills (look for skills section)
    if (preg_match('/skills?:?\s*\n?([\s\S]*?)(?:\n\n|experience|education|projects|$)/i', $raw_text, $match)) {
        $skills_text = $match[1];
        preg_match_all('/[\w\s+#.()-]+[,•\n]/', $skills_text, $skill_matches);
        foreach ($skill_matches[0] as $skill) {
            $skill = trim(preg_replace('/[,•]/', '', $skill));
            if (strlen($skill) > 2 && strlen($skill) < 50) {
                $parsed['skills'][] = $skill;
            }
        }
    }

    // Extract experience
    if (preg_match_all('/(?:experience|employment history|work experience)?.{0,50}?\n([^\n]+?(?:manager|engineer|developer|designer|analyst|architect)[^\n]*)\n([^\n]+)\n([\s\S]{0,500}?)(?=\n\n|\n[A-Z]|$)/i', $raw_text, $matches, PREG_SET_ORDER)) {
        foreach ($matches as $match) {
            $parsed['experience'][] = [
                'role' => trim($match[1]),
                'company' => trim($match[2]),
                'description' => trim(substr($match[3], 0, 200))
            ];
        }
    }

    // Extract certifications
    if (preg_match_all('/(?:certification|certificate|award|achievement)s?:?\s*\n?[-•]\s*([^\n]+)/i', $raw_text, $matches)) {
        $parsed['certifications'] = array_map('trim', $matches[1]);
    }

    // Extract location
    if (preg_match('/(?:location|based|located in|city):\s*([^\n]+)/i', $raw_text, $match)) {
        $parsed['location'] = trim($match[1]);
    } elseif (preg_match('/([A-Z][a-z]+),?\s*[A-Z]{2}/i', $raw_text, $match)) {
        $parsed['location'] = trim($match[0]);
    }

    // Clean up empty arrays
    $parsed['skills'] = array_values(array_unique($parsed['skills']));
    if (count($parsed['skills']) > 20) {
        $parsed['skills'] = array_slice($parsed['skills'], 0, 20);
    }

    return $parsed;
}

/**
 * Loss-minimising resume model shared by AI generation and every template.
 * Unknown text is retained in `unclassified_sections` rather than discarded.
 */
function buildStructuredResumeProfile($rawText) {
    $base = parseResumeContent($rawText);
    $profile = [
        'personal' => ['full_name' => $base['name'], 'professional_title' => $base['job_title']],
        'summary' => $base['about'],
        'contact' => ['email' => $base['email'], 'phone' => $base['phone'], 'location' => $base['location']],
        'socialLinks' => extractResumeLinks($rawText),
        'skills' => ['technical' => [], 'soft' => [], 'other' => []],
        'education' => [], 'experience' => [], 'internships' => [], 'projects' => [],
        'certifications' => [], 'achievements' => [], 'hackathons' => [], 'training' => [],
        'publications' => [], 'volunteerExperience' => [], 'leadership' => [],
        'languages' => [], 'interests' => [], 'unclassified_sections' => []
    ];
    $aliases = [
        'summary'=>'summary|profile|objective|professional summary|about me',
        'skills'=>'skills|technical skills|core competencies|tools|technologies',
        'education'=>'education|academic background|qualifications',
        'experience'=>'experience|work experience|employment|professional experience',
        'internships'=>'internships?|industrial training', 'projects'=>'projects?|selected work|portfolio projects',
        'certifications'=>'certifications?|certificates?|licenses?|credentials?',
        'achievements'=>'achievements?|awards?|honors?|accomplishments?',
        'hackathons'=>'hackathons?|competitions?|contests?', 'training'=>'training|courses?|workshops?',
        'publications'=>'publications?|research', 'volunteerExperience'=>'volunteer(?: experience)?|community service',
        'leadership'=>'leadership|positions? of responsibility', 'languages'=>'languages?', 'interests'=>'interests?|hobbies?'
    ];
    $sections = ['header' => []]; $current = 'header';
    foreach (preg_split('/\R/', str_replace("\r", "", $rawText)) as $line) {
        $line = trim($line); if ($line === '') continue;
        $matched = null;
        foreach ($aliases as $key => $pattern) if (preg_match('/^(' . $pattern . ')\s*:?$/i', $line)) { $matched = $key; break; }
        if ($matched) { $current = $matched; $sections[$current] ??= []; continue; }
        $sections[$current][] = $line;
    }
    $technical = ['php','javascript','typescript','python','java','react','angular','vue','node','sql','mysql','mongodb','aws','azure','docker','kubernetes','git','figma','html','css','api','machine learning','data'];
    $soft = ['communication','leadership','teamwork','problem solving','time management','collaboration','adaptability'];
    foreach (preg_split('/[,;|•]/u', implode("\n", $sections['skills'] ?? [])) as $skill) {
        $skill = trim(preg_replace('/^[-*\d.)\s]+/', '', $skill)); if (strlen($skill) < 2 || strlen($skill) > 100) continue;
        $lower = strtolower($skill); $bucket = 'other';
        foreach ($technical as $word) if (str_contains($lower, $word)) { $bucket = 'technical'; break; }
        foreach ($soft as $word) if (str_contains($lower, $word)) { $bucket = 'soft'; break; }
        $profile['skills'][$bucket][] = $skill;
    }
    foreach ($profile['skills'] as $key => $items) $profile['skills'][$key] = array_values(array_unique($items));
    foreach (['education','experience','internships','projects','certifications','achievements','hackathons','training','publications','volunteerExperience','leadership','languages','interests'] as $key) {
        foreach ($sections[$key] ?? [] as $line) {
            $clean = trim(preg_replace('/^[-*•\x{2022}\d.)\s]+/u', '', $line));
            if ($clean !== '') $profile[$key][] = ['text' => $clean, 'source_text' => $clean];
        }
    }
    foreach ($sections as $key => $lines) if (!isset($aliases[$key]) && $key !== 'header') $profile['unclassified_sections'][$key] = $lines;
    $profile['raw_text'] = $rawText;
    return $profile;
}

function extractResumeLinks($text) {
    preg_match_all('/(?:https?:\/\/|www\.)[^\s,;|)]+/i', $text, $matches);
    $links = [];
    foreach (array_unique($matches[0] ?? []) as $url) {
        $url = rtrim($url, '.'); $normalized = str_starts_with(strtolower($url), 'http') ? $url : 'https://' . $url;
        $platform = 'website'; foreach (['github','linkedin','leetcode','hackerrank','kaggle','behance','dribbble','medium','youtube'] as $name) if (stripos($url, $name) !== false) { $platform = $name; break; }
        $links[] = ['platform' => $platform, 'url' => $normalized];
    }
    return $links;
}
?>
