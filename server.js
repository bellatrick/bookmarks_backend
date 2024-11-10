require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const { auth } = require('express-oauth2-jwt-bearer');
const axios = require('axios');
const cors = require('cors');
const cheerio = require('cheerio');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const app = express();
app.use(express.json());
app.use(cors({
    origin: ['http://localhost:3000',"https://pgbookmarker.netlify.app/" ],
    credentials: true

  }));

// Configure Auth0 middleware
const checkJwt = auth({
  audience: process.env.AUTH0_AUDIENCE,
  issuerBaseURL: process.env.AUTH0_ISSUER
});

// Database connection
const pool = new Pool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '32223', 10),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD
});

// OpenAI setup
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

async function generateEmbedding(text) {
  // For embeddings, use the Text Embeddings model
  const model = genAI.getGenerativeModel({ model: 'text-embedding-004' });
  const result = await model.embedContent(text);
  return `[${result.embedding.values.join(', ')}]`;
}

// Helper function to extract content from URL
async function extractUrlContent(url) {
  const response = await axios.get(url);
  const $ = cheerio.load(response.data);
  return {
    title: $('title').text(),
    description: $('meta[name="description"]').attr('content') || '',
    text: $('body').text().substring(0, 1000) // First 1000 chars for embedding
  };
}

// Routes
app.get('/api/bookmarks', checkJwt, async (req, res) => {
    const auth0Id = req.auth.payload.sub;

    try {
      // Get the user_id based on the auth0_id
      const userResult = await pool.query(
        'SELECT id FROM users WHERE auth0_id = $1',
        [auth0Id]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      const userId = userResult.rows[0].id;

      // Retrieve bookmarks for the user
      const bookmarksResult = await pool.query(
        'SELECT id, user_id, url, title, description, created_at, tags, is_public, share_token FROM bookmarks WHERE user_id = $1',
        [userId]
      );

      res.json(bookmarksResult.rows);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Failed to retrieve bookmarks' });
    }
  });

app.post('/api/bookmarks', checkJwt, async (req, res) => {
  const { url, tags } = req.body;
  const auth0Id = req.auth.payload.sub;
  try {
    // Try to get the user_id from the database based on the auth0_id
    let userResult = await pool.query(
      'SELECT id FROM users WHERE auth0_id = $1',
      [auth0Id]
    );

    let userId;

    // If the user does not exist, create a new user
    if (userResult.rows.length === 0) {
      // Assuming you want to create a new user with the auth0_id
      const createUserResult = await pool.query(
        'INSERT INTO users (auth0_id) VALUES ($1) RETURNING id',
        [auth0Id]
      );
      userId = createUserResult.rows[0].id; // Get the new user's id
    } else {
      // User already exists, get the user_id
      userId = userResult.rows[0].id;
    }

    // Extract content and generate embedding
    const content = await extractUrlContent(url);
    const embedding = await generateEmbedding(
      `${content.title} ${content.description} ${content.text}`
    );

    // Insert bookmark
    const result = await pool.query(
      `INSERT INTO bookmarks (user_id, url, title, description, content_embedding, tags)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *`,
      [userId, url, content.title, content.description, embedding, tags]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create bookmark' });
  }
});

// Search bookmarks by similarity
app.get('/api/bookmarks/search', checkJwt, async (req, res) => {
  const { query } = req.query;
  const auth0Id = req.auth.payload.sub;
  try {
    // Generate embedding for search query
    const searchEmbedding = await generateEmbedding(query);

    const result = await pool.query(
      `SELECT b.*,
              1 - (b.content_embedding <=> $1) as similarity
       FROM bookmarks b
       JOIN users u ON b.user_id = u.id
       WHERE u.auth0_id = $2
       ORDER BY similarity DESC
       LIMIT 10`,
      [searchEmbedding, auth0Id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// Get bookmarks by tag
app.get('/api/bookmarks/tag/:tag', checkJwt, async (req, res) => {
  const { tag } = req.params;
  const auth0Id = req.auth.payload.sub;

  try {
    const result = await pool.query(
      `SELECT b.*
       FROM bookmarks b
       JOIN users u ON b.user_id = u.id
       WHERE u.auth0_id = $1 AND $2 = ANY(b.tags)
       ORDER BY b.created_at DESC`,
      [auth0Id, tag]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch bookmarks' });
  }
});

// Batch processing
const batchSize = 50;

app.post('/api/bookmarks/batch', checkJwt, async (req, res) => {
  const { bookmarks } = req.body; // Array of {url, tags}
  const auth0Id = req.auth.payload.sub;
  const results = [];

  try {
    // Get user_id
    const userResult = await pool.query(
      'SELECT id FROM users WHERE auth0_id = $1',
      [auth0Id]
    );
    const userId = userResult.rows[0].id;

    // Process in batches
    for (let i = 0; i < bookmarks.length; i += batchSize) {
      const batch = bookmarks.slice(i, i + batchSize);
      const batchPromises = batch.map(async (bookmark) => {
        const content = await extractUrlContent(bookmark.url);
        const embedding = await generateEmbedding(
          `${content.title} ${content.description} ${content.text}`
        );

        return pool.query(
          `INSERT INTO bookmarks (user_id, url, title, description, content_embedding, tags)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING *`,
          [
            userId,
            bookmark.url,
            content.title,
            content.description,
            embedding,
            bookmark.tags
          ]
        );
      });

      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults.map((r) => r.rows[0]));
    }

    res.json(results);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Batch processing failed' });
  }
});

app.post('/api/bookmarks/suggest-tags', checkJwt, async (req, res) => {
  const { url } = req.body;

  try {
    const content = await extractUrlContent(url);
    const embedding = await generateEmbedding(
      `${content.title} ${content.description} ${content.text}`
    );

    const result = await pool.query('SELECT * FROM suggest_tags($1, 5)', [
      embedding
    ]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to suggest tags' });
  }
});

// Get collections

app.get('/api/collections', checkJwt, async (req, res) => {
    const auth0Id = req.auth.payload.sub;

    try {
      // Get the user ID from the database based on the auth0_id
      const userResult = await pool.query(
        'SELECT id FROM users WHERE auth0_id = $1',
        [auth0Id]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      const userId = userResult.rows[0].id;

      // Query to get all collections and their associated bookmarks for the user
      const result = await pool.query(
        `
        SELECT
          c.id AS collection_id,
          c.name AS collection_name,
          c.description AS collection_description,
          COALESCE(
            json_agg(
              json_build_object(
                'id', b.id,
                'url', b.url,
                'title', b.title,
                'description', b.description,
                'tags', b.tags,
                'is_public', b.is_public,
                'share_token', b.share_token,
                'created_at', b.created_at
              )
            ) FILTER (WHERE b.id IS NOT NULL), '[]'
          ) AS bookmarks
        FROM collections c
        LEFT JOIN bookmark_collections bc ON c.id = bc.collection_id
        LEFT JOIN bookmarks b ON bc.bookmark_id = b.id
        WHERE c.user_id = $1
        GROUP BY c.id
        `,
        [userId]
      );

      res.json(result.rows); // Send the collections with bookmarks as JSON
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Failed to fetch collections with bookmarks' });
    }
  });



// Create collection
app.post('/api/collections', checkJwt, async (req, res) => {
    const { name, description } = req.body;
    const auth0Id = req.auth.payload.sub;

    try {
      const userResult = await pool.query(
        'SELECT id FROM users WHERE auth0_id = $1',
        [auth0Id]
      );
      const userId = userResult.rows[0].id;

      const result = await pool.query(
        `INSERT INTO collections (user_id, name, description)
         VALUES ($1, $2, $3)
         RETURNING *`,
        [userId, name, description]
      );

      res.json(result.rows[0]);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Failed to create collection' });
    }
  });

  // Add bookmark to collection
  app.post('/api/collections/:collectionId/bookmarks/:bookmarkId', checkJwt, async (req, res) => {
    const { collectionId, bookmarkId } = req.params;
    const auth0Id = req.auth.payload.sub;

    try {
      // Verify ownership
      const authorized = await pool.query(
        `SELECT 1 FROM collections c
         JOIN users u ON c.user_id = u.id
         WHERE c.id = $1 AND u.auth0_id = $2`,
        [collectionId, auth0Id]
      );

      if (authorized.rows.length === 0) {
        return res.status(403).json({ error: 'Unauthorized' });
      }

      await pool.query(
        `INSERT INTO bookmark_collections (bookmark_id, collection_id)
         VALUES ($1, $2)
         ON CONFLICT DO NOTHING`,
        [bookmarkId, collectionId]
      );

      res.json({ success: true });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Failed to add bookmark to collection' });
    }
  });

  app.get('/api/bookmarks/advanced-search', checkJwt, async (req, res) => {
    const { query, tags, dateFrom, dateTo } = req.query;
    const auth0Id = req.auth.payload.sub;

    try {
        // If query is empty, return most recent bookmarks
        if (!query || query.trim() === '') {
            const result = await pool.query(
                `SELECT b.*
                 FROM bookmarks b
                 JOIN users u ON b.user_id = u.id
                 WHERE u.auth0_id = $1
                   AND ($2::text[] IS NULL OR b.tags && $2::text[])
                   AND ($3::timestamp IS NULL OR b.created_at >= $3)
                   AND ($4::timestamp IS NULL OR b.created_at <= $4)
                 ORDER BY b.created_at DESC
                 LIMIT 20`,
                [auth0Id, formattedTags, dateFrom, dateTo]
            );
            return res.json(result.rows);
        }

        const trimmedQuery = query.trim();
        const wordCount = trimmedQuery.split(/\s+/).length;
        const formattedTags = tags ? `{${tags.split(',').map(tag => `"${tag.trim()}"`).join(',')}}` : null;

        // For single-word queries or very short phrases (1-2 words),
        // prioritize exact matches and text search
        if (wordCount <= 2) {
            const result = await pool.query(
                `SELECT b.*,
                        ts_rank(to_tsvector('english', b.title || ' ' || b.description), plainto_tsquery($1)) as text_rank
                 FROM bookmarks b
                 JOIN users u ON b.user_id = u.id
                 WHERE u.auth0_id = $2
                   AND ($3::text[] IS NULL OR b.tags && $3::text[])
                   AND ($4::timestamp IS NULL OR b.created_at >= $4)
                   AND ($5::timestamp IS NULL OR b.created_at <= $5)
                   AND (
                       -- Exact title match
                       LOWER(b.title) LIKE LOWER($6)
                       -- Or text search match
                       OR to_tsvector('english', b.title || ' ' || b.description) @@ plainto_tsquery($1)
                   )
                 ORDER BY
                    CASE
                        WHEN LOWER(b.title) LIKE LOWER($6) THEN 2  -- Prioritize exact matches
                        ELSE ts_rank(to_tsvector('english', b.title || ' ' || b.description), plainto_tsquery($1))
                    END DESC
                 LIMIT 20`,
                [trimmedQuery, auth0Id, formattedTags, dateFrom, dateTo, `%${trimmedQuery}%`]
            );
            return res.json(result.rows);
        }

        // For longer queries, use both semantic and text search
        const searchEmbedding = await generateEmbedding(trimmedQuery);
        const result = await pool.query(
            `SELECT b.*,
                    1 - (b.content_embedding <=> $1) as similarity,
                    ts_rank(to_tsvector('english', b.title || ' ' || b.description), plainto_tsquery($2)) as text_rank
             FROM bookmarks b
             JOIN users u ON b.user_id = u.id
             WHERE u.auth0_id = $3
               AND ($4::text[] IS NULL OR b.tags && $4::text[])
               AND ($5::timestamp IS NULL OR b.created_at >= $5)
               AND ($6::timestamp IS NULL OR b.created_at <= $6)
             ORDER BY
               (1 - (b.content_embedding <=> $1)) * 0.7 +
               ts_rank(to_tsvector('english', b.title || ' ' || b.description), plainto_tsquery($2)) * 0.3 DESC
             LIMIT 20`,
            [searchEmbedding, trimmedQuery, auth0Id, formattedTags, dateFrom, dateTo]
        );

        res.json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Advanced search failed' });
    }
});
  // Make bookmark public
app.post('/api/bookmarks/:id/share', checkJwt, async (req, res) => {
    const { id } = req.params;
    const auth0Id = req.auth.payload.sub;

    try {
      const result = await pool.query(
        `UPDATE bookmarks b
         SET is_public = true
         FROM users u
         WHERE b.id = $1
           AND b.user_id = u.id
           AND u.auth0_id = $2
         RETURNING b.share_token`,
        [id, auth0Id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Bookmark not found' });
      }

      res.json({ shareToken: result.rows[0].share_token });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Failed to share bookmark' });
    }
  });

  // Get shared bookmark
  app.get('/api/shared/:shareToken', async (req, res) => {
    const { shareToken } = req.params;

    try {
      const result = await pool.query(
        `SELECT id, url, title, description, tags
         FROM bookmarks
         WHERE share_token = $1 AND is_public = true`,
        [shareToken]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Shared bookmark not found' });
      }

      res.json(result.rows[0]);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Failed to get shared bookmark' });
    }
  });

  const rateLimit = require('express-rate-limit');

  app.post('/api/bookmarks/with-tags', checkJwt, async (req, res) => {
    const { url } = req.body;
    const auth0Id = req.auth.payload.sub;

    try {
      // Step 1: Retrieve or create the user
      let userResult = await pool.query(
        'SELECT id FROM users WHERE auth0_id = $1',
        [auth0Id]
      );

      let userId;

      if (userResult.rows.length === 0) {
        const createUserResult = await pool.query(
          'INSERT INTO users (auth0_id) VALUES ($1) RETURNING id',
          [auth0Id]
        );
        userId = createUserResult.rows[0].id;
      } else {
        userId = userResult.rows[0].id;
      }

      // Step 2: Suggest tags based on URL content
      const content = await extractUrlContent(url);
      const embedding = await generateEmbedding(
        `${content.title} ${content.description} ${content.text}`
      );

      const tagResults = await pool.query('SELECT * FROM suggest_tags($1, 5)', [embedding]);
      const suggestedTags = tagResults.rows.map(row => row.tag);

      // Step 3: Create the bookmark with the suggested tags
      const bookmarkResult = await pool.query(
        `INSERT INTO bookmarks (user_id, url, title, description, content_embedding, tags)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *`,
        [userId, url, content.title, content.description, embedding, suggestedTags]
      );

      res.json({
        bookmark: bookmarkResult.rows[0],

      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Failed to create bookmark with suggested tags' });
    }
  });

// Create rate limiters
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

const createBookmarkLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50 // limit each IP to 50 bookmark creations per hour
});

// Apply rate limiting to routes
app.use('/api/', apiLimiter);
app.use('/api/bookmarks', createBookmarkLimiter);

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = { generateEmbedding, extractUrlContent };


