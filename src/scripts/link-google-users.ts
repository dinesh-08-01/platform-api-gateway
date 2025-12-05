import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module';
import { FusionAuthClient } from '../auth/fusionauth.client';

/**
 * Script to link existing users with google_id to Google Identity Provider
 * 
 * Usage:
 * 1. Make sure your backend is not running
 * 2. Run: npx ts-node src/scripts/link-google-users.ts
 * 
 * This script will:
 * - Fetch all users from FusionAuth
 * - Find users with google_id in their data
 * - Link them to the Google Identity Provider
 */

async function linkGoogleUsers() {
  console.log('🚀 Starting Google user linking script...\n');

  const app = await NestFactory.createApplicationContext(AppModule);
  const fusionAuthClient = app.get(FusionAuthClient);

  // Google Identity Provider ID from FusionAuth
  const GOOGLE_IDP_ID = '1af47fbc-5156-43c8-89ce-3b5474d55f08';

  try {
    console.log('📋 Fetching all users from FusionAuth...');
    const result = await fusionAuthClient.searchUsers('*', 1000);
    
    console.log(`✅ Found ${result.total} total users\n`);
    
    let linkedCount = 0;
    let skippedCount = 0;
    let errorCount = 0;

    for (const user of result.users) {
      if (user.data?.google_id) {
        try {
          console.log(`🔗 Linking user: ${user.email}`);
          console.log(`   Google ID: ${user.data.google_id}`);
          
          await fusionAuthClient.linkGoogleIdentity(
            user.id,
            user.data.google_id,
            GOOGLE_IDP_ID
          );
          
          console.log(`   ✅ Successfully linked!\n`);
          linkedCount++;
        } catch (error: any) {
          console.error(`   ❌ Failed to link: ${error.message}\n`);
          errorCount++;
        }
      } else {
        console.log(`⏭️  Skipping user: ${user.email} (no google_id)\n`);
        skippedCount++;
      }
    }

    console.log('\n' + '='.repeat(50));
    console.log('📊 LINKING SUMMARY');
    console.log('='.repeat(50));
    console.log(`✅ Successfully linked: ${linkedCount} users`);
    console.log(`⏭️  Skipped: ${skippedCount} users (no google_id)`);
    console.log(`❌ Errors: ${errorCount} users`);
    console.log('='.repeat(50) + '\n');

    if (linkedCount > 0) {
      console.log('🎉 Google user linking completed successfully!');
      console.log('Users with google_id can now sign in with Google.\n');
    } else {
      console.log('ℹ️  No users were linked. This might be because:');
      console.log('   - No users have google_id in their data');
      console.log('   - Users are already linked to Google\n');
    }

  } catch (error: any) {
    console.error('\n❌ Error during linking process:', error.message);
    console.error('Stack trace:', error.stack);
  } finally {
    await app.close();
    console.log('👋 Script completed. Exiting...\n');
  }
}

// Run the script
linkGoogleUsers()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
