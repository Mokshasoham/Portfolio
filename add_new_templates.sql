-- Feature Showcase collection: deliberately distinct from the existing gallery.
INSERT INTO templates (name, slug, description, preview_image, category, is_premium) VALUES
('Data Story', 'data_story', 'Outcome-led portfolio with an impact dashboard, project signals, and a delivery timeline.', 'https://picsum.photos/seed/data-story/600/400', 'professional', 1),
('Product Launch', 'product_launch', 'Conversion-ready case-study portfolio with release milestones, proof points, and product briefs.', 'https://picsum.photos/seed/product-launch/600/400', 'professional', 1),
('Studio Mosaic', 'studio_mosaic', 'Editorial creative portfolio with a responsive work mosaic, selected-work index, and visual storytelling.', 'https://picsum.photos/seed/studio-mosaic/600/400', 'creative', 1)
ON DUPLICATE KEY UPDATE name = VALUES(name), description = VALUES(description), preview_image = VALUES(preview_image), category = VALUES(category), is_premium = VALUES(is_premium);
